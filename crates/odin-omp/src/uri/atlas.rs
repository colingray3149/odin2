//! `atlas://` resolution: immutable snapshots of the allowed atlas scope narrowed by
//! validated path and node prefixes, source classes, and seat categories.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use odin_atlas::AtlasScope;

use super::ScopedUriRouter;
use super::{
    contract::malformed, AtlasNarrowing, UriBody, UriContext, UriError, UriRequest, UriResult,
    UriScheme, JSON_CONTENT_TYPE,
};

impl ScopedUriRouter {
    /// Resolves `atlas://` narrowed to the requested subset of the fixed allowed scope.
    pub fn resolve_atlas(
        &self,
        context: &UriContext,
        url: &str,
        narrowing: &AtlasNarrowing,
    ) -> Result<UriResult, UriError> {
        let request = Self::parse(url)?;
        if request.scheme != UriScheme::Atlas {
            return Err(UriError::Malformed {
                url: request.url,
                reason: "atlas narrowing requires an atlas URI".to_owned(),
            });
        }
        self.resolve_atlas_request(context, request, narrowing)
    }

    pub(super) fn resolve_atlas_request(
        &self,
        _context: &UriContext,
        request: UriRequest,
        narrowing: &AtlasNarrowing,
    ) -> Result<UriResult, UriError> {
        let body = if narrowing_is_unrestricted(narrowing) {
            UriBody::Json(self.atlas.query(&self.allowed_atlas_scope).to_json())
        } else {
            let scope = self.narrowed_atlas_scope(&request.url, narrowing)?;
            UriBody::Json(self.atlas.query(&scope).to_json())
        };
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

    fn narrowed_atlas_scope(
        &self,
        url: &str,
        narrowing: &AtlasNarrowing,
    ) -> Result<AtlasScope, UriError> {
        let allowed = &self.allowed_atlas_scope;

        let source_classes = if narrowing.source_classes.is_empty() {
            allowed.source_classes.clone()
        } else if allowed.source_classes.is_empty() {
            narrowing.source_classes.clone()
        } else {
            let mut keep = BTreeSet::new();
            for class in &narrowing.source_classes {
                if !allowed.source_classes.contains(class) {
                    return Err(UriError::ScopeDenied {
                        url: url.to_owned(),
                        reason: format!(
                            "atlas source class {} is outside the allowed scope",
                            class.as_str()
                        ),
                    });
                }
                keep.insert(*class);
            }
            keep
        };

        // An empty requested axis resolves the whole allowed axis, and an empty allowed axis
        // is already unrestricted; the effective axis can never exceed the allowed one.
        let path_prefixes = if narrowing.path_prefixes.is_empty() {
            allowed.path_prefixes.clone()
        } else {
            let mut path_prefixes = Vec::new();
            for prefix in &narrowing.path_prefixes {
                let normalized = normalized_path_prefix(url, prefix)?;
                if !allowed.path_prefixes.is_empty()
                    && !allowed
                        .path_prefixes
                        .iter()
                        .any(|allowed_prefix| path_within(&normalized, allowed_prefix))
                {
                    return Err(UriError::ScopeDenied {
                        url: url.to_owned(),
                        reason: format!(
                            "atlas path prefix {normalized:?} is outside the allowed scope"
                        ),
                    });
                }
                path_prefixes.push(normalized);
            }
            path_prefixes.sort();
            path_prefixes.dedup();
            path_prefixes
        };

        let node_prefixes = if narrowing.node_prefixes.is_empty() {
            allowed.node_prefixes.clone()
        } else {
            let mut node_prefixes = Vec::new();
            for prefix in &narrowing.node_prefixes {
                let normalized = normalized_node_prefix(url, prefix)?;
                if !allowed.node_prefixes.is_empty()
                    && !allowed
                        .node_prefixes
                        .iter()
                        .any(|allowed_prefix| node_within(&normalized, allowed_prefix))
                {
                    return Err(UriError::ScopeDenied {
                        url: url.to_owned(),
                        reason: format!(
                            "atlas node prefix {normalized:?} is outside the allowed scope"
                        ),
                    });
                }
                node_prefixes.push(normalized);
            }
            node_prefixes.sort();
            node_prefixes.dedup();
            node_prefixes
        };

        let seat_categories = match (&allowed.seat_categories, &narrowing.seat_categories) {
            (None, None) => None,
            (None, Some(requested)) => Some(validated_categories(url, requested)?),
            (Some(_), None) => allowed.seat_categories.clone(),
            (Some(allowed_categories), Some(requested)) => {
                for category in requested {
                    if category != "*" && !allowed_categories.contains(category) {
                        return Err(UriError::ScopeDenied {
                            url: url.to_owned(),
                            reason: format!(
                                "atlas seat category {category:?} is outside the allowed scope"
                            ),
                        });
                    }
                }
                Some(validated_categories(url, requested)?)
            }
        };

        Ok(AtlasScope {
            source_classes,
            path_prefixes,
            node_prefixes,
            seat_categories,
        })
    }
}

fn narrowing_is_unrestricted(narrowing: &AtlasNarrowing) -> bool {
    narrowing.path_prefixes.is_empty()
        && narrowing.node_prefixes.is_empty()
        && narrowing.source_classes.is_empty()
        && narrowing.seat_categories.is_none()
}

fn normalized_path_prefix(url: &str, prefix: &str) -> Result<String, UriError> {
    if prefix.is_empty()
        || prefix
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(malformed(
            url,
            "atlas path prefixes must be non-empty and free of whitespace or control characters",
        ));
    }
    let path = Path::new(prefix);
    if path.is_absolute() {
        return Err(malformed(url, "atlas path prefixes must be relative"));
    }
    let mut normalized = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                return Err(UriError::TraversalRejected {
                    url: url.to_owned(),
                });
            }
            _ => {
                return Err(malformed(
                    url,
                    "atlas path prefixes must contain only normal path components",
                ));
            }
        }
    }
    if normalized.is_empty() {
        return Err(malformed(url, "atlas path prefixes must be non-empty"));
    }
    Ok(normalized.join("/"))
}

fn normalized_node_prefix(url: &str, prefix: &str) -> Result<String, UriError> {
    if prefix.is_empty()
        || prefix
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(malformed(
            url,
            "atlas node prefixes must be non-empty and free of whitespace or control characters",
        ));
    }
    Ok(prefix.to_owned())
}

fn path_within(candidate: &str, allowed: &str) -> bool {
    candidate == allowed
        || (candidate.len() > allowed.len()
            && candidate.starts_with(allowed)
            && candidate.as_bytes()[allowed.len()] == b'/')
}

fn node_within(candidate: &str, allowed: &str) -> bool {
    candidate == allowed
        || candidate
            .strip_prefix(allowed)
            .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('#'))
}

fn validated_categories(
    url: &str,
    categories: &BTreeSet<String>,
) -> Result<BTreeSet<String>, UriError> {
    categories
        .iter()
        .map(|category| {
            if category.is_empty()
                || category
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err(malformed(
                    url,
                    "atlas seat categories must be non-empty and free of whitespace or control characters",
                ));
            }
            Ok(category.clone())
        })
        .collect()
}
