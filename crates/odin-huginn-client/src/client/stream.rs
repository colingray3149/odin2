use odin_domain::huginn::stream::StreamCursor;
use odin_domain::huginn::{HuginnMessage, HuginnRequest};

use super::api::{HuginnTransport, LiveConnection, TransportFrame};
use super::model::ClientError;

pub struct HuginnStream<S, T>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    connection: LiveConnection<S, T>,
    request: Option<HuginnRequest>,
}

impl<S, T> HuginnStream<S, T>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    pub(crate) fn new(connection: LiveConnection<S, T>) -> Self {
        Self {
            connection,
            request: None,
        }
    }

    pub(crate) fn new_request(connection: LiveConnection<S, T>, request: HuginnRequest) -> Self {
        Self {
            connection,
            request: Some(request),
        }
    }

    pub async fn next(&mut self) -> Option<Result<HuginnMessage, ClientError>> {
        self.connection.next().await
    }

    pub fn cursors(&self) -> Vec<StreamCursor> {
        self.connection.cursors()
    }

    pub fn set(&self) -> Option<&odin_domain::huginn::stream::SubscriptionSet> {
        self.connection.subscriptions()
    }

    pub async fn reconnect(&mut self) -> Result<(), ClientError> {
        if let Some(request) = self.request.clone() {
            self.connection.reconnect_request(request).await?;
            Ok(())
        } else {
            let cursors = self.cursors();
            self.connection.reconnect(cursors).await
        }
    }

    pub fn connection_mut(&mut self) -> &mut LiveConnection<S, T> {
        &mut self.connection
    }
}
