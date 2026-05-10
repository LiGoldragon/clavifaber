pub mod certificate_issuer;
pub mod gpg_agent_session;
pub mod host_identity;
pub mod publication_collector;
pub mod runtime_root;
pub mod ssh_host_key;
pub mod trace_recorder;

use crate::error::Error;
use kameo::error::SendError;

pub fn translate_send_error<M>(error: SendError<M, Error>) -> Error
where
    M: std::fmt::Debug,
{
    match error {
        SendError::HandlerError(error) => error,
        other => Error::Parse(format!("actor unavailable: {other}")),
    }
}
