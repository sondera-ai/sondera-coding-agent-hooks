//! Hook event traits shared by every provider adapter.

/// Common contract for CLI hook commands/events that can determine whether they
/// are adjudication-critical.
///
/// Adjudication hooks should fail closed if the governance backend is
/// unavailable. Provider adapters may make narrower, error-kind-aware
/// exceptions for retrospective lifecycle hooks. Observation-only hooks may
/// degrade gracefully.
pub trait HookEvent {
    /// Returns `true` when this hook requires governance adjudication and should
    /// fail closed on initialization or policy errors.
    fn is_adjudication(&self) -> bool;
}
