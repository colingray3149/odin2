//! The live run that serves a cancelled pod's ask.

use super::*;

/// What serves a cancelled pod's ask now. A run names its subject the way
/// `pod_ask` reads it — the workload's company, else the launch's label — so
/// the runs launched for one ask share it by declaration, never by
/// guesswork. The choice among the live runs is [`replacement_among`].
#[derive(Debug, PartialEq)]
pub(super) enum Replacement {
    ServedBy(odin_domain::RunId),
    Ambiguous,
    None,
}

#[cfg(test)]
impl Replacement {
    pub(super) fn run_id(&self) -> &str {
        match self {
            Replacement::ServedBy(run) => run.as_str(),
            _ => "",
        }
    }
}

/// The one live run that serves the cancelled ask's `subject`: two or more
/// same-subject runs are an ambiguity no declaration resolves, and moving the
/// ask onto a guess would close it on a stranger's report; `Ambiguous` says
/// so, and the ask keeps its ordinary follow-through.
pub(super) fn replacement_among(
    cancelled_job: &str,
    subject: &str,
    live: impl IntoIterator<Item = ReplacementRun>,
) -> Replacement {
    let mut candidates = live
        .into_iter()
        .filter(|run: &ReplacementRun| {
            !matches!(
                run.state,
                odin_domain::huginn::KubeWorkloadState::Succeeded
                    | odin_domain::huginn::KubeWorkloadState::Failed
            ) && run.run.as_str() != cancelled_job
                && run.subject.as_deref() == Some(subject)
        })
        .map(|run| run.run);
    match (candidates.next(), candidates.next()) {
        (Some(run), None) => Replacement::ServedBy(run),
        (Some(_), Some(_)) => Replacement::Ambiguous,
        (None, _) => Replacement::None,
    }
}

/// One live run as the replacement choice reads it.
pub(super) struct ReplacementRun {
    pub(super) state: odin_domain::huginn::KubeWorkloadState,
    pub(super) run: odin_domain::RunId,
    /// The workload's company, else the launch's label.
    pub(super) subject: Option<String>,
}

pub(super) async fn replacement_run(
    connected: Option<&odin_huginn::kube::KubeControl>,
    cancelled: &PodAsk,
) -> Replacement {
    let Some(control) = connected else {
        return Replacement::None;
    };
    let reconciler = control.reconciler();
    let Ok(observations) = reconciler.list().await else {
        return Replacement::None;
    };
    let mut live = Vec::with_capacity(observations.len());
    for observation in observations {
        let run = observation.projection.labels.run_id.clone();
        let subject = match reconciler.stored_launch(&run) {
            Ok(Some(launch)) => launch
                .workload
                .as_ref()
                .and_then(|plan| plan.company.clone())
                .or_else(|| launch.label.clone()),
            _ => None,
        };
        live.push(ReplacementRun {
            state: observation.workload.state,
            run,
            subject,
        });
    }
    replacement_among(&cancelled.job, &cancelled.subject, live)
}
