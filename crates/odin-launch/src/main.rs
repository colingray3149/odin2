//! Use the running controller rather than launching models; stdout is reserved for ACP messages.

mod acp;
mod backend;
mod frontend;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use odin_huginn::client::{ColinRemoteClient, EndpointTransport, FileCredentialStore};
use odin_huginn::protocol::CodecLimits;
use odin_huginn::{DeviceCredentialStore as _, OdindConfig, RuntimeManifest};
use tokio::sync::mpsc;

/// The governed ACP frontend of the Odin controller.
#[derive(Debug, Parser)]
#[command(
    name = "odin-acp",
    version,
    about = "Expose the running governed Odin controller as an ACP agent over stdio",
    long_about = None
)]
struct Args {
    /// Path of the composition runtime manifest (`odin.runtime-manifest.v1`).
    #[arg(long, value_name = "PATH", env = "ODIN_RUNTIME_MANIFEST")]
    runtime_manifest: PathBuf,

    /// The declared seat to bind. Explicit values only: no seat default is
    /// ever inferred from configuration or ordering.
    #[arg(long, value_name = "SEAT", env = "ODIN_ACP_SEAT")]
    seat: Option<String>,

    /// The declared project to bind. Explicit values only: no project is
    /// ever inferred from the seat or lane order.
    #[arg(long, value_name = "PROJECT", env = "ODIN_ACP_PROJECT")]
    project: Option<String>,

    /// The declared launch provider this frontend opens fresh sessions
    /// with. Explicit values only: declaration order is never a selection.
    #[arg(long, value_name = "PROVIDER", env = "ODIN_ACP_PROVIDER")]
    provider: Option<String>,

    /// The declared launch model this frontend opens fresh sessions with.
    /// Explicit values only: declaration order is never a selection.
    #[arg(long, value_name = "MODEL", env = "ODIN_ACP_MODEL")]
    model: Option<String>,
}

fn fail(message: &str) -> ! {
    tracing::error!(%message, "odin-acp");
    std::process::exit(1);
}

fn require_explicit(value: Option<String>, what: &str) -> String {
    let value = value.unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fail(&format!(
            "{what} must be set explicitly; this frontend never infers a seat, project, \
             provider, or model"
        ));
    }
    trimmed.to_owned()
}

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let seat = require_explicit(args.seat, "--seat / ODIN_ACP_SEAT");
    let project = require_explicit(args.project, "--project / ODIN_ACP_PROJECT");
    let provider = require_explicit(args.provider, "--provider / ODIN_ACP_PROVIDER");
    let model = require_explicit(args.model, "--model / ODIN_ACP_MODEL");

    // Load the manifest's configuration path so PATH lookup cannot select a different runtime.
    let runtime = RuntimeManifest::load(&args.runtime_manifest)
        .unwrap_or_else(|error| fail(&format!("runtime manifest rejected: {error}")));
    let config = runtime.load_config().unwrap_or_else(|error| {
        fail(&format!(
            "odind config at {} rejected: {error}",
            runtime.odind_config.path.display()
        ))
    });

    let endpoint = backend::endpoint_for(&config).unwrap_or_else(|error| fail(&error));
    let transport =
        EndpointTransport::new(endpoint).unwrap_or_else(|error| fail(&error.to_string()));
    let credential_root = config.paths.state_root.join("huginn");
    let credentials = FileCredentialStore::open(&credential_root)
        .unwrap_or_else(|error| fail(&error.to_string()));
    let credential = credentials
        .load()
        .unwrap_or_else(|error| fail(&error.to_string()))
        .ok_or_else(|| {
            format!(
                "no enrolled device credential exists at {}; pair this loopback workstation \
             first with `odin huginn --state-root {} devices pair --label LABEL --node UUID`",
                credential_root.join("device.credential").display(),
                config.paths.state_root.display()
            )
        })
        .unwrap_or_else(|message| fail(&message));
    let device = credential.device_id().unwrap_or_else(|error| {
        fail(&format!(
            "the enrolled credential has no valid device identity: {error}"
        ))
    });
    let client = ColinRemoteClient::with_limits(transport, credentials, CodecLimits::default());
    let client = Arc::new(client);

    let runtime = tokio::runtime::Runtime::new()
        .unwrap_or_else(|error| fail(&format!("could not start the ACP client runtime: {error}")));
    runtime.block_on(run(client, config, seat, project, provider, model, device));
}

async fn run(
    client: Arc<ColinRemoteClient<EndpointTransport, FileCredentialStore>>,
    config: OdindConfig,
    seat: String,
    project: String,
    provider: String,
    model: String,
    device: odin_domain::huginn::DeviceId,
) {
    // Authenticate before allowing session actions.
    if let Err(error) = client.bootstrap().await {
        fail(&format!("the controller bootstrap failed: {error}"));
    }
    let identity =
        match odin_cli::operator_prompt::operator_identity(&config.paths.state_root, device) {
            Ok(identity) => identity,
            Err(message) => fail(&message),
        };
    tracing::info!(
        seat = %seat,
        project = %project,
        provider = %provider,
        model = %model,
        device = %identity.device_id,
        label = %identity.label,
        "bound; device proven paired and active"
    );

    let approvals = backend::kernel_approvals_reader(config.paths.state_root.clone());
    let opener: Arc<dyn frontend::SessionOpener> = Arc::new(backend::GovernedOpener {
        config,
        seat,
        project,
        provider,
        model,
        client: client.clone(),
        device,
    });
    let (plane, plane_events) = backend::spawn_plane(client.clone());
    // Protocol-only stdout: every ACP message leaves through one writer.
    let (outbound, outbound_receiver) = mpsc::channel::<acp::Message>(256);
    let writer = tokio::spawn(stdout_writer(outbound_receiver));

    let frontend =
        frontend::Frontend::new(client, opener, approvals, plane, plane_events, outbound);
    let outcome = frontend.run(tokio::io::stdin()).await;
    match writer.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => fail(&format!("could not write ACP output: {error}")),
        Err(error) => fail(&format!("ACP output task failed: {error}")),
    }
    match outcome {
        Ok(()) => {
            // EOF or clean close: detach. Durable sessions keep running.
            tracing::info!("stdin closed; detached from every session");
        }
        Err(error) => {
            tracing::error!(message = %error.message, "terminating");
            std::process::exit(1);
        }
    }
}

async fn stdout_writer(mut receiver: mpsc::Receiver<acp::Message>) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let mut stdout = tokio::io::stdout();
    while let Some(message) = receiver.recv().await {
        let mut line = serde_json::to_string(&message).map_err(std::io::Error::other)?;
        line.push('\n');
        stdout.write_all(line.as_bytes()).await?;
        stdout.flush().await?;
    }
    Ok(())
}
