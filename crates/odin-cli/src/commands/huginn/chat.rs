//! `odin huginn chat`: the owner conversation from any paired host. It shows
//! the owner's Discord channel itself (`ConversationThread`), so the pane
//! holds exactly what Discord holds, and says each typed line into it with
//! `ConversationSay`, which the daemon admits exactly like a DM (mirrored
//! into Discord first). Discord edits messages in place — a streamed answer
//! grows through edits — and the pane follows by appending: a shown line
//! whose text changed is printed once more, marked `(edited)`, so nothing
//! already read is rewritten under the reader. Every poll re-reads a bounded snapshot only to catch those edits;
//! new lines always come from the cursor read, in channel order, so the
//! backlog can never print out of order. A lost connection or an
//! unavailable conversation (odind restarting, the network dropping) is
//! retried quietly with backoff that resets only once a request succeeds,
//! and the pane resumes from its cursor; a line said meanwhile is resent
//! under the same command id, so it is admitted once. A line whose fate the
//! daemon cannot tell is held until the owner resends or drops it. Typing, /quit
//! and Ctrl-D stay live throughout; quitting only detaches. The pane writes
//! plain text only — no terminal control sequences — so a redirect or a
//! capture sees exactly what a terminal sees, and what the terminal echoed
//! of the owner's typing is never erased.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use async_trait::async_trait;
use clap::Args;
use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_huginn::client::{ClientError, RemoteClient, EndpointTransport, FileCredentialStore};

#[derive(Debug, Args)]
pub(crate) struct HuginnChatArgs {
    /// Send this one line and exit. Requires `--wait`.
    #[arg(long)]
    say: Option<String>,
    /// Seconds to wait for this say's committed reply.
    #[arg(long)]
    wait: Option<u64>,
}

type Client = RemoteClient<EndpointTransport, FileCredentialStore>;
type Connection = odin_huginn::client::LiveConnection<
    <EndpointTransport as odin_huginn::client::HuginnTransport>::Socket,
    EndpointTransport,
>;

/// How often the channel is re-read (Discord's REST bucket allows far more).
const POLL: Duration = Duration::from_secs(3);
/// How long one request may take before the connection counts as lost.
const REQUEST_BOUND: Duration = Duration::from_secs(20);
/// The longest wait between reconnect attempts.
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// The one line the pane prints while it is reconnecting.
const RECONNECTING: &str = "reconnecting\u{2026}";
/// Shown under a held line.
const HELD: &str = "Check the conversation above: /resend says it again, /drop forgets it.";
/// How many shown lines the pane remembers, the same window the daemon's
/// channel log keeps: a snapshot id that fell out of it is ignored, never
/// appended again.
const REMEMBERED: usize = 200;

/// Why a request did not answer.
#[derive(Debug)]
enum Failure {
    /// The connection is gone or the daemon is restarting: reconnect.
    Lost(String),
    /// Nothing a reconnect fixes (the device was unpaired, a bug).
    Fatal(String),
    /// The daemon cannot tell whether this line reached the conversation
    /// (it was cut off mid-say): shown, and held for the owner to resolve.
    Interrupted(String),
}

/// The pane's link to the conversation.
#[async_trait]
trait Link: Send {
    async fn reconnect(&mut self) -> Result<(), Failure>;
    async fn thread(&mut self, after: Option<String>) -> Result<live::ConversationView, Failure>;
    async fn say(&mut self, request: live::ConversationSayRequest) -> Result<(), Failure>;
    /// Committed reply chunks for this say. `Ok(None)` is not sent yet.
    /// A prior turn's idle session is not a reply.
    async fn committed_reply(&mut self, command_id: &str) -> Result<Option<Vec<String>>, Failure> {
        let _ = command_id;
        Err(Failure::Fatal(
            "this link does not read committed replies".to_owned(),
        ))
    }
}

fn classify(error: ClientError) -> Failure {
    match error {
        error @ (ClientError::ConnectionClosed
        | ClientError::Transport(_)
        | ClientError::Io(_)
        | ClientError::Protocol(live::HuginnProtocolError::Unavailable { .. })) => {
            Failure::Lost(error.to_string())
        }
        ClientError::Protocol(live::HuginnProtocolError::Conflict { code, message })
            if code == "conversationInterrupted" =>
        {
            Failure::Interrupted(message)
        }
        ClientError::DeviceRevoked => {
            Failure::Fatal("this device was unpaired; pair it again to chat".to_owned())
        }
        other => Failure::Fatal(other.to_string()),
    }
}

struct HuginnLink<'client> {
    client: &'client Client,
    connection: Option<Connection>,
}

impl HuginnLink<'_> {
    async fn request(
        &mut self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, Failure> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| Failure::Lost("not connected".to_owned()))?;
        let answer = match tokio::time::timeout(REQUEST_BOUND, connection.request(request)).await {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error)) => classify(error),
            Err(error) => Failure::Lost(format!("no answer within {REQUEST_BOUND:?}: {error}")),
        };
        if matches!(answer, Failure::Lost(_)) {
            self.connection = None;
        }
        Err(answer)
    }
}

#[async_trait]
impl Link for HuginnLink<'_> {
    async fn reconnect(&mut self) -> Result<(), Failure> {
        let connection = tokio::time::timeout(REQUEST_BOUND, self.client.connect())
            .await
            .map_err(|error| {
                Failure::Lost(format!("no connection within {REQUEST_BOUND:?}: {error}"))
            })?
            .map_err(classify)?;
        self.connection = Some(connection);
        Ok(())
    }

    async fn thread(&mut self, after: Option<String>) -> Result<live::ConversationView, Failure> {
        let request =
            live::HuginnRequest::ConversationThread(live::ConversationThreadRequest { after });
        match self.request(request).await? {
            live::HuginnResponse::Conversation(view) => Ok(view),
            other => Err(Failure::Fatal(format!(
                "unexpected conversation response: {other:?}"
            ))),
        }
    }

    async fn say(&mut self, request: live::ConversationSayRequest) -> Result<(), Failure> {
        match self
            .request(live::HuginnRequest::ConversationSay(request))
            .await?
        {
            live::HuginnResponse::Conversation(_) => Ok(()),
            other => Err(Failure::Fatal(format!(
                "unexpected conversation response: {other:?}"
            ))),
        }
    }

    async fn committed_reply(&mut self, command_id: &str) -> Result<Option<Vec<String>>, Failure> {
        let command_id = odin_domain::CommandId::new(command_id)
            .map_err(|error| Failure::Fatal(format!("say command id is not usable: {error}")))?;
        let request =
            live::HuginnRequest::ConversationReply(live::ConversationReplyRequest { command_id });
        match self.request(request).await? {
            live::HuginnResponse::Conversation(view)
                if view.intake.as_deref() == Some("committed") =>
            {
                let chunks: Vec<String> = view
                    .thread
                    .into_iter()
                    .filter(|line| !line.from_owner)
                    .map(|line| line.text)
                    .filter(|text| !text.trim().is_empty())
                    .collect();
                if chunks.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(chunks))
                }
            }
            live::HuginnResponse::Conversation(_) => Ok(None),
            other => Err(Failure::Fatal(format!(
                "unexpected conversation response: {other:?}"
            ))),
        }
    }
}

pub(super) async fn run(
    client: &Client,
    arguments: HuginnChatArgs,
    output: &mut impl Write,
) -> Result<(), String> {
    match (arguments.say, arguments.wait) {
        (None, None) => {
            let (lines_tx, lines) = tokio::sync::mpsc::channel::<String>(8);
            std::thread::spawn(move || {
                let stdin = std::io::stdin();
                let mut line = String::new();
                while matches!(stdin.read_line(&mut line), Ok(read) if read > 0) {
                    if lines_tx.blocking_send(std::mem::take(&mut line)).is_err() {
                        break;
                    }
                }
            });
            let mut link = HuginnLink {
                client,
                connection: None,
            };
            pane(&mut link, lines, output).await
        }
        (Some(text), Some(wait)) if wait > 0 && !text.trim().is_empty() => {
            let mut link = HuginnLink {
                client,
                connection: None,
            };
            say_and_wait(
                &mut link,
                text.trim(),
                Duration::from_secs(wait),
                Duration::from_secs(1),
                output,
            )
            .await
        }
        (Some(_), Some(_)) => {
            Err("chat --wait must be at least 1 and --say must not be empty".to_owned())
        }
        _ => Err("chat --say and --wait are used together".to_owned()),
    }
}

fn fail(error: Failure) -> String {
    match error {
        Failure::Fatal(reason) | Failure::Interrupted(reason) => reason,
        Failure::Lost(reason) => format!("the conversation connection was lost: {reason}"),
    }
}

/// Sends one owner line and prints that say's committed reply. A prior
/// turn's reply, an idle session, and a still-running child are not this
/// reply. The printed text is a refetch after the reply is observed
/// committed, not the observation itself.
async fn say_and_wait(
    link: &mut impl Link,
    text: &str,
    wait: Duration,
    poll: Duration,
    output: &mut impl Write,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut connected = false;
    let request = live::ConversationSayRequest {
        command_id: authority_provision::random_command_uuid()?,
        text: text.to_owned(),
        terminal: true,
    };
    let command_id = request.command_id.as_str().to_owned();
    loop {
        ensure_connected(link, &mut connected, deadline).await?;
        match bounded(deadline, link.say(request.clone())).await? {
            Ok(()) => break,
            Err(Failure::Lost(_)) => {
                connected = false;
                sleep_until(deadline, poll).await?;
            }
            Err(error) => return Err(fail(error)),
        }
    }
    loop {
        ensure_connected(link, &mut connected, deadline).await?;
        let observed = match bounded(deadline, link.committed_reply(&command_id)).await? {
            Ok(chunks) => chunks,
            Err(Failure::Lost(_)) => {
                connected = false;
                sleep_until(deadline, poll).await?;
                continue;
            }
            Err(error) => return Err(fail(error)),
        };
        let ready = observed
            .as_ref()
            .is_some_and(|chunks| chunks.iter().any(|chunk| !chunk.trim().is_empty()));
        if !ready {
            sleep_until(deadline, poll).await?;
            continue;
        }
        let final_reply = match bounded(deadline, link.committed_reply(&command_id)).await? {
            Ok(chunks) => chunks,
            Err(Failure::Lost(_)) => {
                connected = false;
                sleep_until(deadline, poll).await?;
                continue;
            }
            Err(error) => return Err(fail(error)),
        };
        let Some(chunks) = final_reply else {
            sleep_until(deadline, poll).await?;
            continue;
        };
        let replies: Vec<String> = chunks
            .iter()
            .map(|chunk| safe(chunk.trim()))
            .filter(|text| !text.is_empty())
            .collect();
        if replies.is_empty() {
            sleep_until(deadline, poll).await?;
            continue;
        }
        for reply in replies {
            writeln!(output, "{reply}").map_err(io)?;
        }
        return output.flush().map_err(io);
    }
}

async fn ensure_connected(
    link: &mut impl Link,
    connected: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    if *connected {
        return Ok(());
    }
    bounded(deadline, link.reconnect()).await?.map_err(fail)?;
    *connected = true;
    Ok(())
}

async fn bounded<T>(
    deadline: tokio::time::Instant,
    operation: impl Future<Output = Result<T, Failure>>,
) -> Result<Result<T, Failure>, String> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err("timed out waiting for the reply".to_owned());
    }
    match tokio::time::timeout(remaining, operation).await {
        Ok(result) => Ok(result),
        Err(_) => Err("timed out waiting for the reply".to_owned()),
    }
}

async fn sleep_until(deadline: tokio::time::Instant, poll: Duration) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err("timed out waiting for the reply".to_owned());
    }
    tokio::time::sleep(poll.min(remaining)).await;
    Ok(())
}

/// What the pane does next.
enum Step {
    /// Opens the conversation: its newest lines and the seat's name.
    Open,
    Say(live::ConversationSayRequest),
    Read(Option<String>),
}

enum Done {
    Opened(live::ConversationView),
    Said,
    Read {
        snapshot: live::ConversationView,
        incremental: live::ConversationView,
    },
}

/// One step, reconnecting first when the link is down.
async fn perform(link: &mut impl Link, connected: bool, step: Step) -> Result<Done, Failure> {
    if !connected {
        link.reconnect().await?;
    }
    match step {
        Step::Open => link.thread(None).await.map(Done::Opened),
        Step::Say(request) => link.say(request).await.map(|()| Done::Said),
        Step::Read(after) => {
            // The whole-window snapshot re-reads the lines Discord edited in
            // place, which the strictly-after cursor never re-sends; the
            // cursor read then owns every new line and the cursor itself.
            let snapshot = link.thread(None).await?;
            let incremental = link.thread(after).await?;
            Ok(Done::Read {
                snapshot,
                incremental,
            })
        }
    }
}

/// Takes one typed line: `false` once the pane should detach. `/resend`
/// says a held line again under a new command id; `/drop` forgets it.
fn take_line(
    line: Option<String>,
    outbox: &mut std::collections::VecDeque<live::ConversationSayRequest>,
    held: &mut bool,
) -> Result<bool, String> {
    let Some(line) = line else {
        return Ok(false);
    };
    let text = line.trim();
    match text {
        "/quit" => return Ok(false),
        "/resend" | "/drop" if !*held => {}
        "/resend" => {
            if let Some(request) = outbox.front_mut() {
                request.command_id = authority_provision::random_command_uuid()?;
            }
            *held = false;
        }
        "/drop" => {
            outbox.pop_front();
            *held = false;
        }
        "" => {}
        _ => outbox.push_back(live::ConversationSayRequest {
            command_id: authority_provision::random_command_uuid()?,
            text: text.to_owned(),
            terminal: true,
        }),
    }
    Ok(true)
}

/// The lines already on the screen, oldest first, bounded to the channel's
/// remembered window: id to the exact text shown.
#[derive(Default)]
struct Seen {
    lines: std::collections::VecDeque<(String, String)>,
}

impl Seen {
    /// The position of `id` among the shown lines.
    fn position(&self, id: &str) -> Option<usize> {
        self.lines.iter().position(|(shown, _)| shown == id)
    }

    fn remember(&mut self, id: &str, text: &str) {
        self.lines.push_back((id.to_owned(), text.to_owned()));
        while self.lines.len() > REMEMBERED {
            self.lines.pop_front();
        }
    }

    /// The exact text shown for the line at `index`.
    fn text(&self, index: usize) -> &str {
        &self.lines[index].1
    }

    fn update(&mut self, index: usize, text: &str) {
        self.lines[index].1 = text.to_owned();
    }
}

async fn pane(
    link: &mut impl Link,
    mut lines: tokio::sync::mpsc::Receiver<String>,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut outbox = std::collections::VecDeque::new();
    let mut seat: Option<String> = None;
    let mut after: Option<String> = None;
    let mut connected = false;
    // The outbox's first line is held until the owner resends or drops it.
    let mut held = false;
    // The lines already shown, so an edit can be told from a repeat.
    let mut seen = Seen::default();
    // The current backoff while requests fail; `None` while they succeed.
    let mut failing: Option<Duration> = None;
    let mut due = tokio::time::Instant::now();
    loop {
        tokio::select! {
            line = lines.recv() => {
                if !take_line(line, &mut outbox, &mut held)? {
                    return Ok(());
                }
                if failing.is_none() && seat.is_some() {
                    due = tokio::time::Instant::now();
                }
                continue;
            }
            () = tokio::time::sleep_until(due) => {}
        }
        let step = match (&seat, outbox.front()) {
            (None, _) => Step::Open,
            (Some(_), Some(request)) if !held => Step::Say(request.clone()),
            (Some(_), _) => Step::Read(after.clone()),
        };
        let outcome = {
            let attempt = perform(link, connected, step);
            tokio::pin!(attempt);
            loop {
                tokio::select! {
                    outcome = &mut attempt => break outcome,
                    line = lines.recv() => {
                        if !take_line(line, &mut outbox, &mut held)? {
                            return Ok(());
                        }
                    }
                }
            }
        };
        let now = tokio::time::Instant::now();
        match outcome {
            Ok(done) => {
                connected = true;
                failing.take();
                match done {
                    Done::Opened(view) => {
                        writeln!(
                            output,
                            "{} — the same conversation as Discord\n\
                             Type and press Enter to say it (Discord sees it too). /quit or \
                             Ctrl-D detaches.\n",
                            view.seat_id
                        )
                        .map_err(io)?;
                        let name = view.seat_id.to_string();
                        show(&view.thread, &name, &mut seen, false, output)?;
                        after = view.thread.last().map(|line| line.id.clone());
                        seat = Some(name);
                    }
                    Done::Said => {
                        outbox.pop_front();
                    }
                    Done::Read {
                        snapshot,
                        incremental,
                    } => {
                        let name = seat.as_deref().unwrap_or_default();
                        // The snapshot only catches edits to shown lines; the
                        // cursor read owns every new line and the cursor, so
                        // the backlog can never print out of order and a
                        // snapshot past an eviction is never appended again.
                        show(&snapshot.thread, name, &mut seen, true, output)?;
                        show(&incremental.thread, name, &mut seen, false, output)?;
                        after = incremental
                            .thread
                            .last()
                            .map(|line| line.id.clone())
                            .or(after);
                    }
                }
                output.flush().map_err(io)?;
                due = if outbox.is_empty() || held {
                    now + POLL
                } else {
                    now
                };
            }
            Err(Failure::Fatal(reason)) => return Err(reason),
            Err(Failure::Interrupted(reason)) => {
                writeln!(output, "\n{} {HELD}", safe(&reason)).map_err(io)?;
                output.flush().map_err(io)?;
                held = true;
                due = now;
            }
            Err(Failure::Lost(_)) => {
                connected = false;
                let delay = match failing {
                    None => {
                        writeln!(output, "{RECONNECTING}").map_err(io)?;
                        output.flush().map_err(io)?;
                        Duration::from_secs(1)
                    }
                    Some(delay) => (delay * 2).min(RECONNECT_MAX),
                };
                failing = Some(delay);
                due = now + delay;
            }
        }
    }
}

/// Brings the screen to `thread` without ever rewriting it: a line whose id
/// was not shown yet is appended — unless `edits_only`, which leaves unknown
/// ids to the cursor read — and a shown id whose text Discord changed is
/// appended once more, marked `(edited)`.
fn show(
    thread: &[live::ConversationLine],
    seat: &str,
    seen: &mut Seen,
    edits_only: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    for line in thread {
        let text = line_text(line, seat);
        match seen.position(&line.id) {
            Some(index) if seen.text(index) != text => {
                seen.update(index, &text);
                writeln!(output, "{text} (edited)").map_err(io)?;
            }
            Some(_) => {}
            None if !edits_only => {
                seen.remember(&line.id, &text);
                writeln!(output, "{text}").map_err(io)?;
            }
            None => {}
        }
    }
    output.flush().map_err(io)
}

/// The exact text a line occupies (a blank separator line before the
/// owner's), safe for any output.
fn line_text(line: &live::ConversationLine, seat: &str) -> String {
    let mut text = safe(line.text.trim());
    for file in &line.files {
        text.push_str(&format!(" [{}]", safe(file)));
    }
    if line.from_owner {
        format!("\nyou › {text}")
    } else {
        format!("{seat} › {text}")
    }
}

/// Strips terminal control characters a remote string could carry.
fn safe(text: &str) -> String {
    text.chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect()
}

fn io(error: std::io::Error) -> String {
    format!("could not write the conversation: {error}")
}

#[cfg(test)]
mod tests {
    use super::{pane, say_and_wait, show, Failure, Link, Seen};
    use odin_domain::huginn as live;
    use std::collections::VecDeque;

    fn lost() -> Failure {
        Failure::Lost("the fixture dropped the connection".to_owned())
    }

    fn line(id: &str, from_owner: bool, text: &str) -> live::ConversationLine {
        live::ConversationLine {
            id: id.to_owned(),
            from_owner,
            text: text.to_owned(),
            files: Vec::new(),
        }
    }

    /// The pane showed wake envelopes, tool lines, `[quiet]` and host notes
    /// from the seat's history. It shows the owner channel's own messages,
    /// their control characters stripped, keeps the id bookkeeping a read
    /// resumes from, repeats nothing, and prints an edited line once more
    /// marked, never a bare repeat.
    #[test]
    fn the_pane_shows_the_channel_lines_and_keeps_the_cursor() {
        let mut out = Vec::new();
        let mut seen = Seen::default();
        show(
            &[
                line("11", true, "book tea at 3"),
                line(
                    "12",
                    false,
                    "Booked \u{201c}tea\u{201d} for 3:00 PM.\x1b[2J",
                ),
            ],
            "sinmara",
            &mut seen,
            false,
            &mut out,
        )
        .unwrap();
        assert_eq!(seen.position("12"), Some(1));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("you › book tea at 3"), "{text}");
        assert!(
            text.contains("sinmara › Booked “tea” for 3:00 PM.[2J"),
            "{text}"
        );
        // An identical read prints nothing at all.
        let mut quiet = Vec::new();
        show(
            &[
                line("11", true, "book tea at 3"),
                line(
                    "12",
                    false,
                    "Booked \u{201c}tea\u{201d} for 3:00 PM.\x1b[2J",
                ),
            ],
            "sinmara",
            &mut seen,
            false,
            &mut quiet,
        )
        .unwrap();
        assert!(quiet.is_empty());
        // A changed line prints once more, marked.
        let mut edited = Vec::new();
        show(
            &[line("11", true, "book tea at 4")],
            "sinmara",
            &mut seen,
            false,
            &mut edited,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(edited).unwrap(),
            "\nyou › book tea at 4 (edited)\n"
        );
        // An id never shown is left to the cursor read.
        let mut ignored = Vec::new();
        show(
            &[line("99", true, "much later")],
            "sinmara",
            &mut seen,
            true,
            &mut ignored,
        )
        .unwrap();
        assert!(ignored.is_empty());
    }

    fn view(thread: Vec<live::ConversationLine>) -> live::ConversationView {
        live::ConversationView {
            conversation_id: "c".to_owned(),
            seat_id: odin_domain::SeatId::new("sinmara").expect("seat"),
            project_id: odin_domain::ProjectId::new("odin").expect("project"),
            vehicle_session: None,
            previous_vehicle: None,
            intake: None,
            thread,
        }
    }

    /// A daemon that restarts under the pane: reads and says fail as lost
    /// until it is reconnected, the first reconnect fails too. Whole-window
    /// reads (the open and the snapshot) and cursor reads are served from
    /// separate queues, exactly the two roles the pane asks for.
    #[derive(Default)]
    struct Restarting {
        connected: bool,
        reconnects: usize,
        windows: VecDeque<Result<live::ConversationView, ()>>,
        pages: VecDeque<Result<live::ConversationView, ()>>,
        says: Vec<live::ConversationSayRequest>,
        lose_next_say: bool,
        afters: Vec<Option<String>>,
    }

    #[async_trait::async_trait]
    impl Link for Restarting {
        async fn reconnect(&mut self) -> Result<(), Failure> {
            self.reconnects += 1;
            if self.reconnects == 2 {
                return Err(lost());
            }
            self.connected = true;
            Ok(())
        }

        async fn thread(
            &mut self,
            after: Option<String>,
        ) -> Result<live::ConversationView, Failure> {
            self.afters.push(after.clone());
            if !self.connected {
                return Err(lost());
            }
            let queue = if after.is_none() {
                &mut self.windows
            } else {
                &mut self.pages
            };
            match queue.pop_front() {
                Some(Ok(view)) => Ok(view),
                Some(Err(())) => {
                    self.connected = false;
                    Err(lost())
                }
                None => Ok(view(Vec::new())),
            }
        }

        async fn say(&mut self, request: live::ConversationSayRequest) -> Result<(), Failure> {
            self.says.push(request);
            if self.lose_next_say {
                self.lose_next_say = false;
                self.connected = false;
                return Err(lost());
            }
            Ok(())
        }
    }

    /// On an odind restart the pane printed
    /// `odin: transport error: WebSocket protocol error: Connection reset
    /// without closing handshake` and exited. It reconnects by itself, shows
    /// one plain line meanwhile, resumes from its cursor (nothing twice,
    /// nothing lost), and a line said across the drop is admitted once.
    #[tokio::test(start_paused = true)]
    async fn the_pane_rides_out_a_daemon_restart() {
        let mut link = Restarting {
            windows: VecDeque::from([
                Ok(view(vec![line("1", true, "hi")])),
                Err(()),
                Ok(view(vec![line("2", false, "hello")])),
            ]),
            pages: VecDeque::from([Ok(view(vec![line("2", false, "hello")]))]),
            lose_next_say: true,
            ..Restarting::default()
        };
        let (lines_tx, lines) = tokio::sync::mpsc::channel(8);
        lines_tx
            .send("what's on today?\n".to_owned())
            .await
            .unwrap();
        let mut out = Vec::new();
        let driver = async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            lines_tx.send("/quit\n".to_owned()).await.unwrap();
        };
        let (result, ()) = tokio::join!(pane(&mut link, lines, &mut out), driver);
        result.expect("the pane never exits on a lost connection");
        let shown = String::from_utf8(out).unwrap();
        assert!(!shown.contains("error"), "{shown}");
        assert_eq!(shown.matches("you › hi").count(), 1, "{shown}");
        assert_eq!(shown.matches("sinmara › hello").count(), 1, "{shown}");
        assert!(shown.contains("reconnecting\u{2026}"), "{shown}");
        assert_eq!(link.says.len(), 2, "resent once after the drop");
        assert_eq!(link.says[0], link.says[1], "under the same command id");
        let cursors: Vec<&str> = link.afters.iter().flatten().map(String::as_str).collect();
        assert_eq!(cursors.first(), Some(&"1"), "{:?}", link.afters);
        assert!(
            cursors.windows(2).all(|pair| pair[0] <= pair[1]) && cursors.contains(&"2"),
            "the incremental reads advance and never rewind: {:?}",
            link.afters
        );
    }

    /// A daemon whose handshake succeeds while the conversation is
    /// unavailable: every say fails, or never answers at all.
    #[derive(Default)]
    struct Unavailable {
        says: Vec<(tokio::time::Instant, live::ConversationSayRequest)>,
        hang: bool,
        /// Says interrupted; once they are spent, says are accepted.
        interrupt: usize,
        accept: bool,
    }

    #[async_trait::async_trait]
    impl Link for Unavailable {
        async fn reconnect(&mut self) -> Result<(), Failure> {
            Ok(())
        }

        async fn thread(
            &mut self,
            _after: Option<String>,
        ) -> Result<live::ConversationView, Failure> {
            Ok(view(Vec::new()))
        }

        async fn say(&mut self, request: live::ConversationSayRequest) -> Result<(), Failure> {
            self.says.push((tokio::time::Instant::now(), request));
            if self.hang {
                std::future::pending::<()>().await;
            }
            if self.interrupt > 0 {
                self.interrupt -= 1;
                self.accept = true;
                return Err(Failure::Interrupted("cut off".to_owned()));
            }
            if self.accept {
                return Ok(());
            }
            Err(lost())
        }
    }

    /// /quit and Ctrl-D detach even while a say is stuck in flight.
    #[tokio::test(start_paused = true)]
    async fn quitting_detaches_during_a_stuck_say() {
        for quit in [Some("/quit\n"), None] {
            let mut link = Unavailable {
                hang: true,
                ..Unavailable::default()
            };
            let (lines_tx, lines) = tokio::sync::mpsc::channel(8);
            lines_tx.send("hello\n".to_owned()).await.unwrap();
            let driver = async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if let Some(quit) = quit {
                    lines_tx.send(quit.to_owned()).await.unwrap();
                }
            };
            let mut out = Vec::new();
            let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                tokio::join!(pane(&mut link, lines, &mut out), driver)
            })
            .await
            .expect("the pane detached");
            result.expect("detached cleanly");
            assert_eq!(link.says.len(), 1);
        }
    }

    /// A line whose fate the daemon could not tell
    /// was shown and dropped. It is held — never resent by itself, later
    /// lines wait behind it — until the owner drops it or resends it under a
    /// new command id.
    #[tokio::test(start_paused = true)]
    async fn an_interrupted_line_is_held_until_colin_resolves_it() {
        for resend in [false, true] {
            let mut link = Unavailable {
                interrupt: 1,
                ..Unavailable::default()
            };
            let (lines_tx, lines) = tokio::sync::mpsc::channel(8);
            lines_tx.send("yes\n".to_owned()).await.unwrap();
            lines_tx.send("and book tea\n".to_owned()).await.unwrap();
            let driver = async {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                let choice = if resend { "/resend\n" } else { "/drop\n" };
                lines_tx.send(choice.to_owned()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                lines_tx.send("/quit\n".to_owned()).await.unwrap();
            };
            let mut out = Vec::new();
            let (result, ()) = tokio::join!(pane(&mut link, lines, &mut out), driver);
            result.expect("detached");
            let shown = String::from_utf8(out).unwrap();
            assert!(
                shown.contains("cut off") && shown.contains("/resend"),
                "{shown}"
            );
            let said: Vec<&str> = link
                .says
                .iter()
                .map(|(_, request)| request.text.as_str())
                .collect();
            if resend {
                assert_eq!(said, ["yes", "yes", "and book tea"], "{said:?}");
                assert_ne!(link.says[0].1.command_id, link.says[1].1.command_id);
            } else {
                assert_eq!(said, ["yes", "and book tea"], "{said:?}");
            }
        }
    }

    /// A prior turn's reply, and a partial observed before the committed
    /// refetch, are not this say's reply.
    #[tokio::test]
    async fn say_prints_the_reply_only_after_the_session_is_idle() {
        struct Scripted {
            replies: VecDeque<Option<Vec<&'static str>>>,
            reads: usize,
            said: Vec<(String, String)>,
        }
        #[async_trait::async_trait]
        impl Link for Scripted {
            async fn reconnect(&mut self) -> Result<(), Failure> {
                Ok(())
            }
            async fn thread(
                &mut self,
                _: Option<String>,
            ) -> Result<live::ConversationView, Failure> {
                Ok(live::ConversationView {
                    conversation_id: "c".to_owned(),
                    seat_id: odin_domain::SeatId::new("sinmara").unwrap(),
                    project_id: odin_domain::ProjectId::new("odin").unwrap(),
                    vehicle_session: Some(
                        live::LiveSessionId::parse("00000000-0000-4000-8000-0000000000aa").unwrap(),
                    ),
                    previous_vehicle: None,
                    intake: None,
                    thread: vec![line("1", false, "queued-earlier")],
                })
            }
            async fn say(&mut self, request: live::ConversationSayRequest) -> Result<(), Failure> {
                self.said
                    .push((request.command_id.as_str().to_owned(), request.text));
                Ok(())
            }
            async fn committed_reply(
                &mut self,
                command_id: &str,
            ) -> Result<Option<Vec<String>>, Failure> {
                let (said, _) = self.said.last().expect("reply polled before the say");
                assert_eq!(command_id, said, "the wait must follow the submitted say");
                self.reads += 1;
                Ok(self
                    .replies
                    .pop_front()
                    .unwrap_or(None)
                    .map(|chunks| chunks.into_iter().map(str::to_owned).collect()))
            }
        }
        let mut link = Scripted {
            replies: VecDeque::from([None, Some(vec!["71"]), Some(vec!["714"])]),
            reads: 0,
            said: Vec::new(),
        };
        let mut out = Vec::new();
        say_and_wait(
            &mut link,
            "what is 17 times 42",
            std::time::Duration::from_secs(5),
            std::time::Duration::ZERO,
            &mut out,
        )
        .await
        .expect("settled");
        assert_eq!(
            link.said
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>(),
            ["what is 17 times 42"]
        );
        assert_eq!(
            link.reads, 3,
            "a partial must not be printed in place of the refetch"
        );
        let shown = String::from_utf8(out).unwrap();
        assert_eq!(shown, "714\n");
        assert!(!shown.contains("queued-earlier"), "{shown}");
    }
}
