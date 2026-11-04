//! Declared context budgets, resolved by `odin-domain`: slice ceilings
//! minimized with seat ceilings and the model window.

pub use odin_domain::knowledge::context::{
    resolve_context_policy, EffectiveContextPolicy, SeatContextPolicy, SliceContextPolicy,
};
pub use odin_domain::knowledge::retrieval::ModelDescriptor;
