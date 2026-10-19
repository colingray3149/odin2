//! Typed workload-image identity (`odin.workload-image-identity.v1`).
//!
//! The confined workload image emits one `identity.json` beside its OCI
//! archive: the exact manifest/config digests the reference pins, every
//! in-image tool binding with its store path and BLAKE3, and the module
//! roots. It is the single contract between the image build and runtime
//! admission: the pinned Odin extension entrypoint lives in `tools.extension`
//! with `in_image` (the path the remote launch binds as `--trusted-extension`)
//! and `blake3` (the exact shipped entrypoint bytes). Admission compares a
//! composed [`crate::extension_policy::ExtensionPolicyV1`] extension digest
//! against exactly that value — never against a path or a name.
//!
//! Parsing is strict (`deny_unknown_fields`): an identity that does not match
//! the emitted schema byte-for-byte in shape is a typed refusal, never a
//! partially trusted document.

use serde::{Deserialize, Serialize};

pub const WORKLOAD_IMAGE_IDENTITY_SCHEMA: &str = "odin.workload-image-identity.v1";

/// One in-image tool binding: the absolute in-image path, the resolved store
/// path it links to, and (for executable and module bindings that carry one)
/// the BLAKE3 of the exact bytes the image ships at that path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageToolIdentity {
    pub in_image: String,
    pub store: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
}

/// The pinned Odin extension entrypoint binding: the single contract spelling
/// admission composes the remote extension policy from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageExtensionIdentity {
    /// Absolute in-image path of the extension entrypoint the remote launch
    /// binds as `--trusted-extension`.
    pub in_image: String,
    /// Resolved in-image store path of the same file.
    pub store: String,
    /// BLAKE3 (`blake3:<64 hex>`) of the exact `index.ts` bytes shipped in the
    /// image layer. Admission composes the policy extension digest from this
    /// value and compares it back before any effect.
    pub blake3: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageToolsIdentity {
    pub omp: ImageToolIdentity,
    pub odin: ImageToolIdentity,
    pub odind: ImageToolIdentity,
    pub node: ImageToolIdentity,
    pub chromium: ImageToolIdentity,
    pub xvfb: ImageToolIdentity,
    /// The pinned Odin extension entrypoint. Present on every identity the
    /// current image contract emits; a remote extension launch without it is
    /// a typed refusal.
    pub extension: ImageExtensionIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageModuleRootIdentity {
    pub in_image: String,
    pub store: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageModuleRootsIdentity {
    pub playwright: ImageModuleRootIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageConfigIdentity {
    pub user: String,
    pub working_dir: String,
    pub entrypoint: Option<String>,
    pub command: Option<String>,
    pub env: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadImageIdentity {
    pub schema: String,
    pub reference: String,
    pub image_name: String,
    pub tag: String,
    /// `sha256:<64 hex>` OCI manifest/index digest the reference pins. This —
    /// never the name or the tag — is the value admission compares against a
    /// workload profile's digest-pinned image reference.
    pub manifest_digest: String,
    pub config_digest: String,
    pub import_archive: String,
    pub omp_source_revision: String,
    pub archive_sha256: String,
    pub source_revision: String,
    pub tools: ImageToolsIdentity,
    pub module_roots: ImageModuleRootsIdentity,
    pub mount_points: Vec<String>,
    pub config: ImageConfigIdentity,
}

impl WorkloadImageIdentity {
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        let identity: Self = serde_json::from_slice(bytes).map_err(|error| {
            DomainError::InvalidEnvelope(format!(
                "workload image identity bytes are not valid strict JSON: {error}"
            ))
        })?;
        identity.validate()?;
        Ok(identity)
    }

    /// Checks schema, digests, reference consistency, and absolute extension paths;
    /// other build-emitted fields are not interpreted.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema != WORKLOAD_IMAGE_IDENTITY_SCHEMA {
            return Err(DomainError::InvalidEnvelope(format!(
                "workload image identity schema must be {WORKLOAD_IMAGE_IDENTITY_SCHEMA:?}, \
                 found {:?}",
                self.schema
            )));
        }
        if !valid_sha256_digest(&self.manifest_digest) {
            return Err(DomainError::InvalidEnvelope(format!(
                "workload image identity manifest digest {:?} is not `sha256:<64 hex>`",
                self.manifest_digest
            )));
        }
        if !valid_sha256_digest(&self.config_digest) {
            return Err(DomainError::InvalidEnvelope(format!(
                "workload image identity config digest {:?} is not `sha256:<64 hex>`",
                self.config_digest
            )));
        }
        if self.reference != format!("{}@{}", self.image_name, self.manifest_digest) {
            return Err(DomainError::InvalidEnvelope(
                "workload image identity reference must be `image_name@manifest_digest`".to_owned(),
            ));
        }
        validate_blake3(&self.tools.extension.blake3)?;
        if !self.tools.extension.in_image.starts_with('/') {
            return Err(DomainError::InvalidEnvelope(format!(
                "workload image identity extension in_image {:?} must be an absolute in-image \
                 path",
                self.tools.extension.in_image
            )));
        }
        Ok(())
    }

    pub fn extension(&self) -> &ImageExtensionIdentity {
        &self.tools.extension
    }

    /// True when this identity is the identity of exactly the given
    /// digest-pinned OCI reference: the reference's `@sha256:<hex>` suffix
    /// must equal `manifest_digest`. The manifest digest is the only trust
    /// anchor — a name or tag match proves nothing.
    pub fn pins_reference(&self, image_reference: &str) -> bool {
        image_reference.split('@').nth(1) == Some(self.manifest_digest.as_str())
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Uses the extension-policy digest format: `blake3:` followed by 64 lowercase hex digits.
fn validate_blake3(value: &str) -> Result<(), DomainError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(DomainError::InvalidEnvelope(format!(
            "workload image identity extension blake3 {value:?} must start with `blake3:`"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(DomainError::InvalidEnvelope(format!(
            "workload image identity extension blake3 {value:?} must be `blake3:` plus 64 \
             lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

use crate::DomainError;

#[cfg(test)]
mod tests {
    use super::*;

    /// Image-emitted fixture including `tools.extension`.
    fn sample_bytes() -> Vec<u8> {
        serde_json::json!({
            "schema": WORKLOAD_IMAGE_IDENTITY_SCHEMA,
            "reference": "localhost/odin-workload@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428",
            "image_name": "localhost/odin-workload",
            "tag": "18.1.18-c3k9b4ljsj9h",
            "manifest_digest": "sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428",
            "config_digest": "sha256:b8a188f01192d0a857dd4fe1e469cc3217ef4757acbfc4abfc7db804aa46112e",
            "import_archive": "odin-workload-image-oci.tar",
            "omp_source_revision": "00085d4e7dfdcfbf302c122fa2682b410a0f43d1",
            "archive_sha256": "63045bbd2d848ff1702b2366f359a69b06ed485451f8ea1411fc963b0af04326",
            "source_revision": "c3k9b4ljsj9hdwbna37r644b8l471cyj",
            "tools": {
                "omp": {
                    "in_image": "/odin/bin/omp",
                    "store": "/nix/store/q9d42swrbrrzfjr7ahmgrs2r1cwag940-omp-18.1.18/bin/omp",
                    "blake3": "blake3:f85cc84dd70a78c09b4d99dccaadca7b0935e35a30b568bb6038c2714cf37cda"
                },
                "odin": {
                    "in_image": "/odin/bin/odin",
                    "store": "/nix/store/c3k9b4ljsj9hdwbna37r644b8l471cyj-odin-0.0.0/bin/odin",
                    "blake3": "blake3:7494a9efea0995fe1ad2c8dacdb1d9afc0c856def5785b3dc9ade9de9593f1c5"
                },
                "odind": {
                    "in_image": "/odin/bin/odind",
                    "store": "/nix/store/c3k9b4ljsj9hdwbna37r644b8l471cyj-odin-0.0.0/bin/odind",
                    "blake3": "blake3:e5defddcdbc6ecfa8c3a53252404e9fcdbb7f716eb6be4e6e6e5a8ece06e4551"
                },
                "node": {
                    "in_image": "/odin/bin/node",
                    "store": "/nix/store/2gd4h12irmnanhg33md2rpjygrsj5ypb-nodejs-slim-22.23.2/bin/node",
                    "blake3": "blake3:f5c4477e866cddea8e44623400f2c28cf0773398f38de4cde9cf390448e7b74c"
                },
                "chromium": {
                    "in_image": "/odin/bin/chromium",
                    "store": "/nix/store/3qgx41z8882ff85y9prdc5zgbb2id6y8-chromium-152.0.7977.64/bin/chromium",
                    "blake3": "blake3:b82d1bafb8339c402fdba594fb639849c93c4e3ee1671a9b5741c48a385235b5"
                },
                "xvfb": {
                    "in_image": "/odin/bin/Xvfb",
                    "store": "/nix/store/2ngsl5s8gmkbvav54pg2khb5ykxc4d10-xvfb-21.1.24/bin/Xvfb",
                    "blake3": "blake3:bf39900803fa36f3ab95e89d7b5bb04648982b0dbb1b44c881f6b0431140d2ed"
                },
                "extension": {
                    "in_image": "/odin/lib/odin-extension/index.ts",
                    "store": "/nix/store/00000000000000000000000000000000-odin-extension/index.ts",
                    "blake3": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            },
            "module_roots": {
                "playwright": {
                    "in_image": "/odin/lib/playwright-core",
                    "store": "/odin/lib/playwright-core"
                }
            },
            "mount_points": ["/state", "/export"],
            "config": {
                "user": "65534:65534",
                "working_dir": "/state",
                "entrypoint": serde_json::Value::Null,
                "command": serde_json::Value::Null,
                "env": ["PATH=/odin/bin:/bin", "HOME=/state"]
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn parses_the_image_emitted_shape_and_exposes_the_extension_binding() {
        let identity = WorkloadImageIdentity::parse(&sample_bytes()).expect("identity parses");
        assert_eq!(
            identity.extension().in_image,
            "/odin/lib/odin-extension/index.ts"
        );
        assert!(identity.extension().blake3.starts_with("blake3:"));
    }

    #[test]
    fn pins_only_the_exact_manifest_digest_of_a_reference() {
        let identity = WorkloadImageIdentity::parse(&sample_bytes()).expect("identity parses");
        let pinned = "localhost/odin-workload:18.1.18@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428";
        assert!(identity.pins_reference(pinned));
        // A different manifest digest is a different image even when the
        // repository and tag match: the pin is the only anchor.
        let other = "localhost/odin-workload@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513429";
        assert!(!identity.pins_reference(other));
        assert!(!identity.pins_reference("localhost/odin-workload:18.1.18"));
    }

    #[test]
    fn unknown_fields_and_wrong_schema_are_typed_refusals() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&sample_bytes()).expect("sample value");
        value["surprise"] = serde_json::Value::Bool(true);
        assert!(WorkloadImageIdentity::parse(value.to_string().as_bytes()).is_err());

        let mut stale: serde_json::Value =
            serde_json::from_slice(&sample_bytes()).expect("sample value");
        stale["schema"] = serde_json::Value::from("odin.workload-image-identity.v2");
        assert!(WorkloadImageIdentity::parse(stale.to_string().as_bytes()).is_err());
    }

    #[test]
    fn malformed_digest_or_relative_extension_path_is_a_typed_refusal() {
        let mut bad_digest: serde_json::Value =
            serde_json::from_slice(&sample_bytes()).expect("sample value");
        bad_digest["tools"]["extension"]["blake3"] = serde_json::Value::from(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(WorkloadImageIdentity::parse(bad_digest.to_string().as_bytes()).is_err());

        let mut relative: serde_json::Value =
            serde_json::from_slice(&sample_bytes()).expect("sample value");
        relative["tools"]["extension"]["in_image"] =
            serde_json::Value::from("lib/odin-extension/index.ts");
        assert!(WorkloadImageIdentity::parse(relative.to_string().as_bytes()).is_err());
    }
}
