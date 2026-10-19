//! Compile and validate skeleton fills in private staging without publishing live changes.

use crate::schema::RegistryObject;

mod compile;
mod contracts;
mod staging;
mod validation;
mod values;

pub use compile::{
    compile_fill_documents, patch_container_source, AuthoringDestination, CompiledDocument,
    CompiledFill, ContainerPatch, AUTHORING_FILL_SCHEMA,
};
pub use contracts::{
    AuthoringErrors, AuthoringIssue, FillDocumentSource, FillRequest, FillValues, SkeletonCatalog,
    SkeletonContract, SkeletonKind, SkeletonVariable, SKELETON_PATCH_SCHEMA,
    SKELETON_VARIABLE_SCHEMA,
};
pub use install::install_staged_batch;
pub use staging::{
    stage_fill, stage_fill_batch, StagedChange, StagedDiffMetadata, StagedFill, StagedFillBatch,
};
pub use validation::validate_fill_batch;

mod install;

#[derive(Clone, Debug)]
pub struct ValidatedFill {
    compiled: CompiledFill,
    combined: Vec<RegistryObject>,
}

impl ValidatedFill {
    pub const fn compiled(&self) -> &CompiledFill {
        &self.compiled
    }

    pub fn combined(&self) -> &[RegistryObject] {
        &self.combined
    }
}

/// Validate relations after applying the entire batch so cross-file references see the combined state.
#[derive(Clone, Debug)]
pub struct ValidatedFillBatch {
    compiled: Vec<CompiledFill>,
    combined: Vec<RegistryObject>,
}

impl ValidatedFillBatch {
    pub fn compiled(&self) -> &[CompiledFill] {
        &self.compiled
    }

    pub fn combined(&self) -> &[RegistryObject] {
        &self.combined
    }
}
