mod api;
mod cli;
mod model;
mod stream;
mod transfer;

pub use api::{
    memory_transport, memory_transport_for_peer, ColinRemoteClient, EndpointSocket,
    EndpointTransport, HuginnTransport, LiveConnection, MemoryClientEnd, MemoryServerEnd,
    MemoryServerHub, MemoryTransport, TransportFrame,
};
pub use cli::{
    protocol_request_for, request_kind, CliCommandMapping, CommandRoute, CLI_COMMAND_MAPPINGS,
};
pub use model::{
    BootstrapInfo, ClientError, DeviceCredential, DeviceCredentialStore, FileCredentialStore,
    MemoryCredentialStore, DEVICE_CREDENTIAL_BYTES,
};
pub use stream::HuginnStream;
pub use transfer::{DownloadSink, FileSink, MemorySink, UploadSource, UploadTarget};
