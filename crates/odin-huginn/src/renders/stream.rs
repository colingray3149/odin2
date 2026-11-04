use futures_util::stream;
use odin_domain::huginn::{HuginnProtocolError, RenderStatus, RenderStatusStream};
use tokio::sync::watch;

pub(crate) fn status_stream(receiver: watch::Receiver<RenderStatus>) -> RenderStatusStream {
    let stream = stream::unfold((receiver, true), |(mut receiver, initial)| async move {
        if initial {
            let status = receiver.borrow_and_update().clone();
            return Some((Ok(status), (receiver, false)));
        }
        if receiver.changed().await.is_err() {
            return None;
        }
        let status = receiver.borrow_and_update().clone();
        Some((Ok::<_, HuginnProtocolError>(status), (receiver, false)))
    });
    Box::pin(stream)
}
