//! `atlas://` resolution: the immutable snapshot of the constructor-injected allowed scope.
//! The scope is the deployment's, not the caller's; per-seat narrowing is the `atlas.query` host tool.

use std::sync::Arc;

use odin_atlas::Atlas;

use super::ScopedUriRouter;
use super::{UriBody, UriError, UriRequest, UriResult, JSON_CONTENT_TYPE};

impl ScopedUriRouter {
    pub(super) fn resolve_atlas(&self, request: UriRequest) -> Result<UriResult, UriError> {
        let body = UriBody::Json(
            self.built_atlas(&request.url)?
                .query(&self.allowed_atlas_scope)
                .to_json(),
        );
        Ok(UriResult {
            request,
            content_type: JSON_CONTENT_TYPE.to_owned(),
            immutable: true,
            notes: vec![
                "atlas snapshot restricted to the constructor-injected allowed scope".to_owned(),
            ],
            body,
        })
    }

    /// The knowledge index once odind has built it; before that, `atlas://` is typed-unavailable.
    fn built_atlas(&self, url: &str) -> Result<&Atlas, UriError> {
        self.atlas
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| UriError::ConfigurationRejected {
                detail: format!(
                    "{url} is unavailable: the knowledge index is still building after startup; \
                     retry shortly"
                ),
            })
    }
}
