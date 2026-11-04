//! Media times: numeric seconds or colon-separated hours, minutes and seconds.
use serde_json::Value;

use crate::Failure;

pub fn parse(value: &Value, field: &str) -> Result<f64, Failure> {
    let seconds = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => {
            let mut count = 0;
            text.trim().split(':').try_fold(0.0, |total, part| {
                count += 1;
                let value = part.parse::<f64>().ok()?;
                (count <= 3 && value.is_finite() && value >= 0.0 && (count == 1 || value < 60.0))
                    .then_some(total * 60.0 + value)
            })
        }
        _ => None,
    };
    seconds
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .ok_or_else(|| {
            Failure::arguments(format!(
                "{field} must be seconds or a time like 0:12 or 1:02:03.5, not {value}"
            ))
        })
}

pub fn opt(args: &Value, field: &str) -> Result<Option<f64>, Failure> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse(value, field).map(Some),
    }
}

/// A rounded time for a sentence, such as `3:42` or `1:02:03`.
pub fn clock(seconds: f64) -> String {
    let whole = seconds.round() as u64;
    let (hours, minutes, seconds) = (whole / 3600, whole / 60 % 60, whole % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// A time for a filename, rounded to tenths of a second.
pub fn tag(seconds: f64) -> String {
    let tenths = (seconds * 10.0).round() / 10.0;
    format!("{tenths}s")
}

#[cfg(test)]
mod tests {}
