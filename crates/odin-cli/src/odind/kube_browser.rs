//! Relay an agent pod's browser container to the authority's browser runtime.

use std::sync::Arc;

use odin_cli::browser_runtime;
use odin_domain::huginn as live;
use odin_kube::exec::{decompose, exec_fixed, WorkloadExecStream, WorkloadLauncherSpec};

/// The host side of one pod browser relay: the kube exec of the pod's
/// one-use `odind browser-connect` attach in its browser container, handed
/// over as the relayed worker transport. Closing it never stops the pod.
struct KubeBrowserRelay {
    stream: WorkloadExecStream,
}

impl odin_browser::relay::WorkerRelay for KubeBrowserRelay {
    fn split(self: Box<Self>) -> odin_browser::relay::RelayedStreams {
        let WorkloadExecStream {
            stdin,
            stdout,
            stderr,
            exit,
            ..
        } = self.stream;
        odin_browser::relay::RelayedStreams {
            stdin,
            stdout,
            exit,
            stderr: stderr.unwrap_or_else(|| Box::new(tokio::io::empty())),
        }
    }
}

/// The browser-connect attach argv of one pod browser session: the pod's
/// pinned supervisor binary, the container-private socket, and the session
/// the one-use activation carries.
fn browser_connect_spec(
    agent: &odin_kube::workload::WorkloadAgentPlan,
    session: &live::BrowserSessionId,
) -> WorkloadLauncherSpec {
    WorkloadLauncherSpec {
        launcher_path: agent.supervisor.clone(),
        arguments: vec![
            "browser-connect".to_owned(),
            "--socket".to_owned(),
            odin_kube::workload::BROWSER_SOCKET.to_owned(),
            "--session".to_owned(),
            session.to_string(),
        ],
    }
}

/// The declared screen `<w>x<h>x<depth>` as the browser viewport.
fn screen_viewport(screen: &str) -> Option<odin_browser::config::Viewport> {
    let mut parts = screen.split('x');
    let width = parts.next()?.parse().ok()?;
    let height = parts.next()?.parse().ok()?;
    Some(odin_browser::config::Viewport::new(
        std::num::NonZeroU32::new(width)?,
        std::num::NonZeroU32::new(height)?,
    ))
}

/// How long the pod browser waits for its carrier's browser container to
/// run: the agent attach and the browser open race the pod's start.
const POD_BROWSER_ATTACH_WINDOW: std::time::Duration = std::time::Duration::from_secs(180);

/// Opens one agent pod's own browser: attaches the browser-connect relay
/// to the run's browser container (waiting while the carrier starts),
/// then opens the relayed session under the authority's browser policy.
pub(super) async fn open_pod_browser(
    client: odin_kube::KubeClient,
    run: odin_domain::RunId,
    plan: odin_kube::workload::WorkloadPodPlan,
    session: live::BrowserSessionId,
    routes: Arc<browser_runtime::BrowserRoutes>,
) {
    let outcome = async {
        let agent = plan
            .agent
            .as_ref()
            .ok_or_else(|| "the workload runs no agent harness".to_owned())?;
        let viewport = screen_viewport(&agent.display.screen)
            .ok_or_else(|| "the declared screen is not <w>x<h>x<depth>".to_owned())?;
        let spec = browser_connect_spec(agent, &session);
        let deadline = tokio::time::Instant::now() + POD_BROWSER_ATTACH_WINDOW;
        let attached = loop {
            match exec_fixed(
                &client,
                &run,
                odin_kube::exec::JobExecTarget::Browser,
                &spec,
            )
            .await
            {
                Ok(attached) => break attached,
                Err(odin_kube::exec::WorkloadExecError::NotRunning { .. })
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(error) => return Err(format!("browser relay attach: {error}")),
            }
        };
        let stream = decompose(attached).map_err(|error| error.to_string())?;
        let paths = odin_browser::relay::RelayedWorkerPaths::for_session(
            std::path::Path::new(&format!("{}/browser", plan.state_mount)),
            &session,
            agent.playwright.clone(),
            agent.browser.clone(),
        );
        let mut identity = format!("pod:{run}");
        identity.truncate(128);
        routes
            .open_pod(
                session,
                browser_runtime::PodBrowserLaunch {
                    relay: Box::new(KubeBrowserRelay { stream }),
                    paths,
                    viewport,
                    identity,
                    navigate_hosts: plan.allow_hosts.clone(),
                    stream: agent.display.stream,
                },
            )
            .await
    }
    .await;
    match outcome {
        Ok(()) => tracing::info!("pod browser {session} open for run {run}"),
        Err(error) => {
            routes.release(&session);
            tracing::error!("pod browser {session} for run {run} did not open: {error}");
        }
    }
}
