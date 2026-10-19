//! Routines use the seat's existing capabilities and approvals; triggers grant no additional permission.

use std::collections::BTreeSet;

use odin_domain::SeatId;
use serde::{Deserialize, Serialize};

use super::object::RegistryKind;

/// Limit routine text to one prompt or message.
pub const ROUTINE_TEXT_MAX_CHARS: usize = 2_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub seat: SeatId,
    pub trigger: RoutineTriggerToml,
    pub action: RoutineActionToml,
}

/// Require exactly one trigger so scheduling and event semantics cannot overlap.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineTriggerToml {
    /// Calendar recurrence uses the owner's current timezone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<RoutineEvent>,
    /// Narrows a workload event to one pod profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Event-specific filter: mail query, title or file words, project ID, or gesture name.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
    /// For `calendar_event`: how many minutes before the event starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_minutes: Option<u16>,
    /// Absence watches every readable mail or calendar account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

pub const ROUTINE_MATCH_MAX_CHARS: usize = 200;

impl RoutineTriggerToml {
    /// Match gestures case-insensitively; no filter accepts any gesture.
    pub fn follows_gesture(&self, made: &str) -> bool {
        self.matches
            .as_deref()
            .is_none_or(|gesture| made.trim().eq_ignore_ascii_case(gesture.trim()))
    }

    pub fn check_event(&self, event: RoutineEvent) -> Result<(), String> {
        if self.profile.is_some() && !event.concerns_a_pod() {
            return Err(format!(
                "trigger.profile narrows a pod event, not {}",
                event.as_str()
            ));
        }
        if let Some(text) = &self.matches {
            let length = text.trim().chars().count();
            if length == 0 || length > ROUTINE_MATCH_MAX_CHARS {
                return Err(format!(
                    "trigger.match must be 1..={ROUTINE_MATCH_MAX_CHARS} characters"
                ));
            }
            if event.concerns_a_pod() || event == RoutineEvent::Incident {
                return Err(format!(
                    "trigger.match narrows a mail, calendar, file, repo or ring event, not {}",
                    event.as_str()
                ));
            }
        }
        if event == RoutineEvent::MailArrived && self.matches.is_none() {
            return Err(
                "a mail_arrived routine names the mail it follows in trigger.match \
                 (e.g. a sender or subject words)"
                    .to_owned(),
            );
        }
        match (event, self.lead_minutes) {
            (RoutineEvent::CalendarEvent, Some(1..=1440)) => {}
            (RoutineEvent::CalendarEvent, _) => {
                return Err(
                    "a calendar_event routine declares trigger.lead_minutes in 1..=1440".to_owned(),
                )
            }
            (_, Some(_)) => {
                return Err(format!(
                    "trigger.lead_minutes belongs to calendar_event, not {}",
                    event.as_str()
                ))
            }
            (_, None) => {}
        }
        if self.account.is_some()
            && !matches!(
                event,
                RoutineEvent::MailArrived | RoutineEvent::CalendarEvent
            )
        {
            return Err(format!(
                "trigger.account narrows a mail or calendar event, not {}",
                event.as_str()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutineEvent {
    WorkloadSucceeded,
    WorkloadFailed,
    Watchdog,
    /// An incident of warning severity or above was raised.
    Incident,
    MailArrived,
    CalendarEvent,
    FileReceived,
    /// Includes pushes from any source, not just Odin.
    RepoPush,
    /// No gesture filter accepts any gesture.
    RingGesture,
}

impl RoutineEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkloadSucceeded => "workload_succeeded",
            Self::WorkloadFailed => "workload_failed",
            Self::Watchdog => "watchdog",
            Self::Incident => "incident",
            Self::MailArrived => "mail_arrived",
            Self::CalendarEvent => "calendar_event",
            Self::FileReceived => "file_received",
            Self::RepoPush => "repo_push",
            Self::RingGesture => "ring_gesture",
        }
    }

    pub const fn concerns_a_pod(self) -> bool {
        matches!(
            self,
            Self::WorkloadSucceeded | Self::WorkloadFailed | Self::Watchdog
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineActionToml {
    pub kind: RoutineActionKind,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutineActionKind {
    /// Run a conversation turn with the seat's existing tools.
    Brief,
    /// Deliver the text unchanged without running a model.
    Dm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockTime {
    pub hour: u8,
    pub minute: u8,
}

/// The parsed recurrence grammar:
///
/// - `daily 07:30`, `weekdays 07:30`, `weekends 10:00`
/// - `mon,wed,fri 16:00` (any of `mon tue wed thu fri sat sun`)
/// - `monthly 1 09:00` (day 1..=28, so every month has it)
/// - `every 30 minutes`, `every 2 hours` (5 minutes ..= 24 hours, counted
///   from local midnight)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutineSchedule {
    /// Weekdays numbered Monday = 1 ..= Sunday = 7.
    Weekly {
        days: BTreeSet<u8>,
        at: ClockTime,
    },
    Monthly {
        day: u8,
        at: ClockTime,
    },
    Every {
        minutes: u32,
    },
}

const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

impl RoutineSchedule {
    pub fn parse(text: &str) -> Result<Self, String> {
        let words: Vec<String> = text
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let clock = |word: &str| -> Result<ClockTime, String> {
            let (hour, minute) = word
                .split_once(':')
                .ok_or_else(|| format!("{word:?} is not a time like 07:30"))?;
            let hour: u8 = hour
                .parse()
                .map_err(|_| format!("{word:?} is not a time like 07:30"))?;
            let minute: u8 = minute
                .parse()
                .map_err(|_| format!("{word:?} is not a time like 07:30"))?;
            if hour > 23 || minute > 59 || word.len() != 5 {
                return Err(format!("{word:?} is not a time like 07:30"));
            }
            Ok(ClockTime { hour, minute })
        };
        match words.as_slice() {
            ["every", count, unit] => {
                let count: u32 = count
                    .parse()
                    .map_err(|_| format!("{count:?} is not a whole number"))?;
                let minutes = match *unit {
                    "minute" | "minutes" => count,
                    "hour" | "hours" => count.saturating_mul(60),
                    other => return Err(format!("{other:?} is not minutes or hours")),
                };
                if !(5..=1440).contains(&minutes) {
                    return Err("a repeating routine runs every 5 minutes to every 24 hours".into());
                }
                Ok(Self::Every { minutes })
            }
            ["monthly", day, time] => {
                let day: u8 = day
                    .parse()
                    .map_err(|_| format!("{day:?} is not a day of the month"))?;
                if !(1..=28).contains(&day) {
                    return Err(
                        "a monthly routine runs on day 1..=28, which every month has".into(),
                    );
                }
                Ok(Self::Monthly {
                    day,
                    at: clock(time)?,
                })
            }
            [days, time] => {
                let days: BTreeSet<u8> = match *days {
                    "daily" => (1..=7).collect(),
                    "weekdays" => (1..=5).collect(),
                    "weekends" => (6..=7).collect(),
                    list => list
                        .split(',')
                        .map(|name| {
                            DAY_NAMES
                                .iter()
                                .position(|known| *known == name)
                                .map(|index| index as u8 + 1)
                                .ok_or_else(|| {
                                    format!(
                                        "{name:?} is not daily, weekdays, weekends or a day \
                                         like mon"
                                    )
                                })
                        })
                        .collect::<Result<_, _>>()?,
                };
                Ok(Self::Weekly {
                    days,
                    at: clock(time)?,
                })
            }
            _ => Err(format!(
                "{text:?} is not a schedule like \"weekdays 07:30\", \"mon,wed 16:00\", \
                 \"monthly 1 09:00\" or \"every 30 minutes\""
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_event_trigger_takes_only_its_own_narrowing() {
        let trigger =
            |matches: Option<&str>, lead: Option<u16>, account: Option<&str>| RoutineTriggerToml {
                schedule: None,
                event: None,
                profile: None,
                matches: matches.map(str::to_owned),
                lead_minutes: lead,
                account: account.map(str::to_owned),
            };
        use RoutineEvent::*;
        assert!(trigger(Some("from:prof"), None, Some("me@x"))
            .check_event(MailArrived)
            .is_ok());
        assert!(trigger(None, None, None).check_event(MailArrived).is_err());
        assert!(trigger(Some("ME 11"), Some(30), None)
            .check_event(CalendarEvent)
            .is_ok());
        assert!(trigger(None, None, None)
            .check_event(CalendarEvent)
            .is_err());
        assert!(trigger(None, Some(0), None)
            .check_event(CalendarEvent)
            .is_err());
        assert!(trigger(None, Some(30), None)
            .check_event(MailArrived)
            .is_err());
        assert!(trigger(Some("surtr"), None, None)
            .check_event(RepoPush)
            .is_ok());
        assert!(trigger(Some("surtr"), None, Some("me@x"))
            .check_event(RepoPush)
            .is_err());
        assert!(trigger(None, None, None).check_event(FileReceived).is_ok());
        assert!(trigger(Some("double-tap"), None, None)
            .check_event(RingGesture)
            .is_ok());
        assert!(trigger(None, None, None).check_event(RingGesture).is_ok());
        assert!(trigger(Some("double-tap"), Some(5), None)
            .check_event(RingGesture)
            .is_err());
        assert!(trigger(Some("double-tap"), None, Some("me@x"))
            .check_event(RingGesture)
            .is_err());
        assert!(trigger(Some("double-tap"), None, None).follows_gesture("Double-Tap"));
        assert!(!trigger(Some("double-tap"), None, None).follows_gesture("double-tap-hold"));
        assert!(!trigger(Some("double-tap"), None, None).follows_gesture("shake"));
        assert!(trigger(None, None, None).follows_gesture("shake"));
        assert!(trigger(Some("x"), None, None)
            .check_event(WorkloadSucceeded)
            .is_err());
        assert!(trigger(Some(""), None, None)
            .check_event(FileReceived)
            .is_err());
    }

    /// The grammar Sinmara writes from Colin's words: what parses, and what
    /// is refused with a reason she can act on.
    #[test]
    fn the_schedule_grammar_parses_calendar_recurrences_and_refuses_the_rest() {
        let at = |hour, minute| ClockTime { hour, minute };
        assert_eq!(
            RoutineSchedule::parse("weekdays 07:30"),
            Ok(RoutineSchedule::Weekly {
                days: (1..=5).collect(),
                at: at(7, 30)
            })
        );
        assert_eq!(
            RoutineSchedule::parse("Mon,Wed,Fri 16:00"),
            Ok(RoutineSchedule::Weekly {
                days: [1, 3, 5].into_iter().collect(),
                at: at(16, 0)
            })
        );
        assert_eq!(
            RoutineSchedule::parse("monthly 1 09:00"),
            Ok(RoutineSchedule::Monthly {
                day: 1,
                at: at(9, 0)
            })
        );
        assert_eq!(
            RoutineSchedule::parse("every 2 hours"),
            Ok(RoutineSchedule::Every { minutes: 120 })
        );
        for refused in [
            "weekdays 7:30",
            "weekdays 24:00",
            "monthly 31 09:00",
            "every 1 minutes",
            "every 2 days",
            "someday 07:30",
            "tomorrow",
        ] {
            assert!(RoutineSchedule::parse(refused).is_err(), "{refused}");
        }
    }
}
