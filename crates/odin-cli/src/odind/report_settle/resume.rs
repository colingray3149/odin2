//! What a pod's final answer leaves unmet, and whether it goes back to the pod for them.

use super::*;

/// What a final answer leaves undone, as the authority acts on it.
#[derive(Clone, Default)]
pub(super) struct Undone {
    /// The unmet items, and notes of what the settlement itself cut short.
    pub(super) items: Vec<String>,
    /// The authority's own receipts that unmet items named: those items are not the pod's to
    /// finish and are left out of `items`.
    pub(super) receipts: Vec<String>,
}

impl Undone {
    /// What `answer` says it left unmet: nothing from a turn that failed.
    pub(super) fn of(answer: &str, failed: bool) -> Self {
        let mut undone = Self::default();
        if failed {
            return undone;
        }
        for item in unmet_items(answer) {
            let name = unmet_name(&item);
            let named: Vec<&str> = AUTHORITY_RECEIPTS
                .into_iter()
                .filter(|receipt| name.contains(receipt))
                .collect();
            match named.is_empty() {
                true => undone.items.push(item),
                false => undone.receipts.extend(named.into_iter().map(str::to_owned)),
            }
        }
        undone.receipts.sort_unstable();
        undone.receipts.dedup();
        undone
    }

    /// Adds the receipts another answer's unmet items named.
    pub(super) fn name_receipts(&mut self, receipts: &[String]) {
        self.receipts.extend(receipts.iter().cloned());
        self.receipts.sort_unstable();
        self.receipts.dedup();
    }
}

/// What a pod's final answer that lists unmet items is due.
pub(super) enum Resume {
    /// Back to the pod now.
    Now,
    /// Back to the pod at the next review cycle.
    Wait,
    /// Settled as it stands: no wall time to spare, or nothing new to try.
    Spent,
}

/// Unmet items go back to the pod once per review cycle while at least two cycles of wall time
/// remain, at most [`MAX_UNMET_RESUMES`] times, and not again when its answer to the last resume
/// names the same items (by what each leads with, since the pod rewords the methods it tried):
/// that pod has nothing further to try. A pod whose deadline or cycle is unknown is not resumed.
pub(super) fn resume_decision(wall: Wall, state: &SettlementState, unmet: &[String]) -> Resume {
    let (Some(left), Some(cycle)) = (wall.left, wall.cycle) else {
        return Resume::Spent;
    };
    let resumed = state.resumed_at != 0;
    fn names<'a>(items: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
        items.map(unmet_name).collect()
    }
    let unchanged =
        resumed && names(state.resumed_unmet.lines()) == names(unmet.iter().map(String::as_str));
    if left < 2 * cycle || state.resumes >= MAX_UNMET_RESUMES || unchanged {
        Resume::Spent
    } else if resumed && wall.now - state.resumed_at < cycle {
        Resume::Wait
    } else {
        Resume::Now
    }
}

pub(super) fn resume_with_unmet(
    records: &Path,
    state: &mut SettlementState,
    wall: Wall,
    unmet: &[String],
) -> ReportSettlement {
    state.resumed_at = wall.now;
    state.resumes = state.resumes.saturating_add(1);
    state.resumed_unmet = unmet.join("\n");
    if let Err(error) = write_state(records, state) {
        return ReportSettlement::Pending {
            note: format!("The resume was not recorded, so the pod was not resumed: {error}"),
            follow_up: None,
        };
    }
    let minutes = wall.left.unwrap_or(0) / 60;
    let items: Vec<String> = unmet.iter().map(|item| format!("- {item}")).collect();
    ReportSettlement::Pending {
        note: format!(
            "Resuming the pod with {} unmet launch-input item(s); {minutes} minutes remain",
            unmet.len()
        ),
        follow_up: Some(ReviewTurn {
            text: format!(
                "Your final answer leaves launch-input items unmet, and {minutes} minutes of \
                 wall time remain. Unmet items:\n{}\nDo them now. For each, use a method you have \
                 not tried on it yet: another read engine such as Obscura, the browser, a dated \
                 archive copy or a different search. Answer again when done. End the answer with \
                 an \"Unmet items\" list of whatever is still not done, each with the methods \
                 tried on it, or with \"Unmet items: none\".",
                items.join("\n")
            ),
            images: Vec::new(),
        }),
    }
}

/// The unmet items of a partial report, one per line with the methods tried on it, and the
/// receipts the authority did not count as unmet.
pub(super) fn unmet_note(undone: &Undone) -> String {
    let mut note = String::new();
    if !undone.items.is_empty() {
        let items: Vec<String> = undone
            .items
            .iter()
            .map(|item| format!("- {item}"))
            .collect();
        note = format!(
            "\nUnmet items, with the methods tried on each:\n{}",
            items.join("\n")
        );
    }
    if !undone.receipts.is_empty() {
        note.push_str(&format!(
            "\nNot counted as unmet: {}, which the authority writes itself and the pod cannot.",
            undone.receipts.join(", ")
        ));
    }
    note
}
