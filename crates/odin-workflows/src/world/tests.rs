use serde_json::json;
use url::Url;

use super::weather::{choose, day_rows, sky};
use super::{home, Place};

fn forecast() -> serde_json::Value {
    json!({"daily": {
        "time": ["2026-11-13", "2026-11-14", "2026-11-15", "2026-11-16"],
        "weather_code": [0, 61, 3, 95],
        "temperature_2m_max": [76.2, 64.0, 70.0, 68.0],
        "temperature_2m_min": [55.1, 52.0, 50.0, 51.0],
        "precipitation_probability_max": [0, 80, 10, 60],
        "precipitation_sum": [0.0, 0.42, 0.0, 0.1],
        "wind_speed_10m_max": [8.0, 15.0, 6.0, 20.0],
        "uv_index_max": [4.1, 2.0, 3.0, 1.0],
        "sunrise": ["2026-11-13T06:25", "2026-11-14T06:26", "2026-11-15T06:27", "2026-11-16T06:28"],
        "sunset": ["2026-11-13T16:49", "2026-11-14T16:48", "2026-11-15T16:48", "2026-11-16T16:47"],
    }})
}

#[test]
fn tomorrow_a_weekday_the_weekend_and_a_date_pick_their_days() {
    let days = day_rows(&forecast());
    let today = "2026-11-13"; // a Friday
    let dates = |when: &str| {
        choose(&days, today, when)
            .unwrap()
            .iter()
            .map(|day| day.date.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(dates("today"), ["2026-11-13"]);
    assert_eq!(dates("tomorrow"), ["2026-11-14"]);
    assert_eq!(dates("sunday"), ["2026-11-15"]);
    assert_eq!(dates("weekend"), ["2026-11-14", "2026-11-15"]);
    assert_eq!(dates("2026-11-16"), ["2026-11-16"]);
    assert_eq!(dates("week").len(), 4);
    let beyond = choose(&days, today, "2026-12-25").unwrap_err();
    assert!(
        beyond.cause.contains("runs 2026-11-13 to 2026-11-16"),
        "{}",
        beyond.cause
    );
}

#[test]
fn a_day_reads_as_one_line() {
    let days = day_rows(&forecast());
    assert_eq!(
        days[1].line("2026-11-13"),
        "Tomorrow Saturday 11-14: light rain, 52–64°F, 80% rain, 0.42 in, wind to 15 mph, UV 2, sun 06:26–16:48"
    );
    assert_eq!(sky(Some(95)), "thunderstorms");
}

#[test]
fn home_is_a_geo_uri_with_its_name() {
    let url = Url::parse("geo:38.8977,-77.0365#Washington").unwrap();
    assert_eq!(
        home(&url).unwrap(),
        Place {
            name: "Washington".to_owned(),
            latitude: 38.8977,
            longitude: -77.0365,
            country: Some("US".to_owned()),
        }
    );
    assert!(home(&Url::parse("https://example.com/").unwrap()).is_err());
}
