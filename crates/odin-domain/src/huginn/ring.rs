//! Paired devices report gestures to `ring_gesture` routines; device credentials are the report's only authority.

use serde::{Deserialize, Serialize};

pub const RING_GESTURE_NAME_MAX_CHARS: usize = 40;
pub const RING_GESTURE_ID_MAX_CHARS: usize = 80;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RingGestureReport {
    /// Unique per recognized gesture on the reporting device: a retried
    /// report with the same id fires nothing new.
    pub gesture_id: String,
    /// The gesture's name, lowercase `[a-z0-9-]`.
    pub gesture: String,
}

impl RingGestureReport {
    pub fn check(&self) -> Result<(), String> {
        let name = &self.gesture;
        if name.is_empty()
            || name.chars().count() > RING_GESTURE_NAME_MAX_CHARS
            || !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "a gesture name is 1..={RING_GESTURE_NAME_MAX_CHARS} characters of a-z, 0-9 and '-'"
            ));
        }
        let id = &self.gesture_id;
        if id.is_empty()
            || id.chars().count() > RING_GESTURE_ID_MAX_CHARS
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return Err(format!(
                "a gesture id is 1..={RING_GESTURE_ID_MAX_CHARS} characters of A-Z, a-z, 0-9 and -_.:"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: &str, gesture: &str) -> RingGestureReport {
        RingGestureReport {
            gesture_id: id.to_owned(),
            gesture: gesture.to_owned(),
        }
    }

    #[test]
    fn the_report_shape_is_checked() {
        assert!(report("1759573200-3", "double-tap").check().is_ok());
        for bad in [
            report("", "double-tap"),
            report("a b", "double-tap"),
            report("1", ""),
            report("1", "Double-Tap"),
            report("1", "-tap"),
            report("1", &"x".repeat(41)),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let json = r#"{"gestureId":"7","gesture":"shake"}"#;
        let parsed: RingGestureReport = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, report("7", "shake"));
        assert!(serde_json::from_str::<RingGestureReport>(
            r#"{"gestureId":"7","gesture":"x","extra":1}"#
        )
        .is_err());
    }
}
