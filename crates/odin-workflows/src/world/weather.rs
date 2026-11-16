//! world.weather: the forecast for a day or a few, the current conditions
//! today, active weather alerts (US, from the NWS), air quality and the sun.

use serde_json::{json, Value};

use super::{endpoint, get, place, Place};
use crate::{args, Call, Ctx, Failure};

const FORECAST_DAYS: usize = 7;

pub fn run(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let place = place(ctx, args::opt_str(input, "place"))?;
    let when = args::opt_str(input, "when")
        .unwrap_or("today")
        .trim()
        .to_lowercase();
    let forecast = forecast(ctx, &place)?;
    let days = day_rows(&forecast);
    let today = days
        .first()
        .map(|day| day.date.clone())
        .ok_or_else(|| Failure::upstream("the forecast came back without days"))?;
    let chosen = choose(&days, &today, &when)?;
    let mut lines = Vec::new();
    if chosen.first().is_some_and(|day| day.date == today) {
        if let Some(now) = current_line(&forecast) {
            lines.push(format!("{} now: {now}", place.name));
        }
    }
    for day in &chosen {
        lines.push(day.line(&today));
    }
    let mut unavailable = Vec::new();
    let alerts = if place.country.as_deref() == Some("US") {
        match alerts(ctx, &place) {
            Ok(alerts) => alerts,
            Err(failure) => {
                unavailable.push(format!("alerts: {}", failure.cause));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    lines.extend(alerts.iter().map(|alert| format!("Alert: {alert}")));
    if chosen.first().is_some_and(|day| day.date == today) {
        match air(ctx, &place) {
            Ok(Some(line)) => lines.push(line),
            Ok(None) => {}
            Err(failure) => unavailable.push(format!("air: {}", failure.cause)),
        }
    }
    let mut answer = json!({
        "done": lines.join("\n"),
        "place": place.name,
        "days": chosen.iter().map(|day| day.value()).collect::<Vec<_>>(),
        "alerts": alerts,
    });
    if !unavailable.is_empty() {
        answer["unavailable"] = json!(unavailable);
    }
    Ok(answer)
}

fn forecast(ctx: &Ctx, place: &Place) -> Result<Value, Failure> {
    let mut url = endpoint(ctx, "open-meteo", "v1/forecast")?;
    url.query_pairs_mut()
        .append_pair("latitude", &place.latitude.to_string())
        .append_pair("longitude", &place.longitude.to_string())
        .append_pair(
            "daily",
            "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max,\
             precipitation_sum,wind_speed_10m_max,uv_index_max,sunrise,sunset",
        )
        .append_pair(
            "current",
            "temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m",
        )
        .append_pair("temperature_unit", "fahrenheit")
        .append_pair("wind_speed_unit", "mph")
        .append_pair("precipitation_unit", "inch")
        .append_pair("timezone", "auto")
        .append_pair("forecast_days", &FORECAST_DAYS.to_string());
    get(ctx, &url)
}

/// One forecast day, in the place's own calendar.
#[derive(Debug, PartialEq)]
pub(super) struct Day {
    pub date: String,
    code: Option<u64>,
    high: Option<f64>,
    low: Option<f64>,
    rain_chance: Option<f64>,
    rain: Option<f64>,
    wind: Option<f64>,
    uv: Option<f64>,
    sunrise: Option<String>,
    sunset: Option<String>,
}

pub(super) fn day_rows(forecast: &Value) -> Vec<Day> {
    let daily = &forecast["daily"];
    let column = |key: &str, index: usize| daily[key].get(index).cloned().unwrap_or(Value::Null);
    let clock = |value: Value| {
        value
            .as_str()
            .and_then(|text| text.split_once('T'))
            .map(|(_, time)| time.to_owned())
    };
    daily["time"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, date)| {
            Some(Day {
                date: date.as_str()?.to_owned(),
                code: column("weather_code", index).as_u64(),
                high: column("temperature_2m_max", index).as_f64(),
                low: column("temperature_2m_min", index).as_f64(),
                rain_chance: column("precipitation_probability_max", index).as_f64(),
                rain: column("precipitation_sum", index).as_f64(),
                wind: column("wind_speed_10m_max", index).as_f64(),
                uv: column("uv_index_max", index).as_f64(),
                sunrise: clock(column("sunrise", index)),
                sunset: clock(column("sunset", index)),
            })
        })
        .collect()
}

/// The days `when` names: today, tomorrow, a weekday, a date, or the week.
pub(super) fn choose<'a>(
    days: &'a [Day],
    today: &str,
    when: &str,
) -> Result<Vec<&'a Day>, Failure> {
    let pick = |index: usize| days.get(index).into_iter().collect::<Vec<_>>();
    let chosen = match when {
        "" | "now" | "today" | "tonight" => pick(0),
        "tomorrow" => pick(1),
        "week" | "this week" | "next days" | "forecast" => days.iter().collect(),
        "weekend" | "this weekend" => days
            .iter()
            .filter(|day| matches!(weekday(&day.date), Some(5 | 6)))
            .take(2)
            .collect(),
        other => {
            if let Some(target) = WEEKDAYS
                .iter()
                .position(|name| other.trim_start_matches("next ").starts_with(&name[..3]))
            {
                days.iter()
                    .skip(1)
                    .filter(|day| weekday(&day.date) == Some(target as u8))
                    .take(1)
                    .collect()
            } else {
                days.iter().filter(|day| day.date == other).collect()
            }
        }
    };
    if chosen.is_empty() {
        let last = days.last().map_or(today, |day| day.date.as_str());
        return Err(Failure::arguments(format!(
            "{when:?} is not in the forecast, which runs {today} to {last}; ask for today, tomorrow, a weekday, the weekend, the week or a date"
        )));
    }
    Ok(chosen)
}

const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

/// 0 = Monday … 6 = Sunday, for a `YYYY-MM-DD` date.
fn weekday(date: &str) -> Option<u8> {
    let date = time::Date::parse(
        date,
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()?;
    Some(date.weekday().number_days_from_monday())
}

impl Day {
    fn label(&self, today: &str) -> String {
        let name = weekday(&self.date)
            .map(|index| WEEKDAYS[index as usize])
            .unwrap_or("");
        let mut name = name.to_owned();
        if let Some(first) = name.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        let relative = match weekday(today).zip(weekday(&self.date)) {
            _ if self.date == today => "Today ",
            Some((now, then)) if (now + 1) % 7 == then => "Tomorrow ",
            _ => "",
        };
        format!("{relative}{name} {}", &self.date[5..])
    }

    pub(super) fn line(&self, today: &str) -> String {
        let mut parts = vec![sky(self.code).to_owned()];
        if let (Some(low), Some(high)) = (self.low, self.high) {
            parts.push(format!("{}–{}°F", low.round(), high.round()));
        }
        match (self.rain_chance, self.rain) {
            (Some(chance), Some(inches)) if inches >= 0.01 => {
                parts.push(format!("{}% rain, {inches:.2} in", chance.round()));
            }
            (Some(chance), _) => parts.push(format!("{}% rain", chance.round())),
            _ => {}
        }
        if let Some(wind) = self.wind {
            parts.push(format!("wind to {} mph", wind.round()));
        }
        if let Some(uv) = self.uv {
            parts.push(format!("UV {}", uv.round()));
        }
        if let (Some(rise), Some(set)) = (&self.sunrise, &self.sunset) {
            parts.push(format!("sun {rise}–{set}"));
        }
        format!("{}: {}", self.label(today), parts.join(", "))
    }

    fn value(&self) -> Value {
        json!({
            "date": self.date, "sky": sky(self.code), "highF": self.high, "lowF": self.low,
            "rainChance": self.rain_chance, "rainInches": self.rain, "windMph": self.wind,
            "uv": self.uv, "sunrise": self.sunrise, "sunset": self.sunset,
        })
    }
}

fn current_line(forecast: &Value) -> Option<String> {
    let current = &forecast["current"];
    let temperature = current["temperature_2m"].as_f64()?;
    let mut line = format!(
        "{}, {}°F",
        sky(current["weather_code"].as_u64()),
        temperature.round()
    );
    if let Some(feels) = current["apparent_temperature"].as_f64() {
        if (feels - temperature).abs() >= 3.0 {
            line.push_str(&format!(" (feels {}°F)", feels.round()));
        }
    }
    if let Some(humidity) = current["relative_humidity_2m"].as_f64() {
        line.push_str(&format!(", humidity {}%", humidity.round()));
    }
    if let Some(wind) = current["wind_speed_10m"].as_f64() {
        line.push_str(&format!(", wind {} mph", wind.round()));
    }
    Some(line)
}

/// WMO weather interpretation codes in words.
pub(super) fn sky(code: Option<u64>) -> &'static str {
    match code {
        Some(0) => "clear",
        Some(1) => "mostly clear",
        Some(2) => "partly cloudy",
        Some(3) => "overcast",
        Some(45 | 48) => "fog",
        Some(51 | 53 | 55) => "drizzle",
        Some(56 | 57) => "freezing drizzle",
        Some(61) => "light rain",
        Some(63) => "rain",
        Some(65) => "heavy rain",
        Some(66 | 67) => "freezing rain",
        Some(71) => "light snow",
        Some(73) => "snow",
        Some(75) => "heavy snow",
        Some(77) => "snow grains",
        Some(80 | 81) => "showers",
        Some(82) => "violent showers",
        Some(85 | 86) => "snow showers",
        Some(95) => "thunderstorms",
        Some(96 | 99) => "thunderstorms with hail",
        _ => "unknown sky",
    }
}

/// Active NWS alerts at the place: "Wind Advisory until …".
fn alerts(ctx: &Ctx, place: &Place) -> Result<Vec<String>, Failure> {
    let mut url = endpoint(ctx, "nws", "alerts/active")?;
    url.query_pairs_mut().append_pair(
        "point",
        &format!("{:.4},{:.4}", place.latitude, place.longitude),
    );
    let found = get(ctx, &url)?;
    Ok(found["features"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|feature| {
            let properties = &feature["properties"];
            let event = properties["event"].as_str()?;
            let until = properties["ends"]
                .as_str()
                .or(properties["expires"].as_str())
                .map(|until| {
                    format!(
                        " until {}",
                        until.replace('T', " ").get(..16).unwrap_or(until)
                    )
                });
            Some(format!("{event}{}", until.unwrap_or_default()))
        })
        .collect())
}

/// "Air: AQI 42 (good)", from Open-Meteo's current US AQI.
fn air(ctx: &Ctx, place: &Place) -> Result<Option<String>, Failure> {
    let mut url = endpoint(ctx, "open-meteo-air", "v1/air-quality")?;
    url.query_pairs_mut()
        .append_pair("latitude", &place.latitude.to_string())
        .append_pair("longitude", &place.longitude.to_string())
        .append_pair("current", "us_aqi")
        .append_pair("timezone", "auto");
    let found = get(ctx, &url)?;
    Ok(found["current"]["us_aqi"].as_f64().map(|aqi| {
        let word = match aqi.round() as u64 {
            0..=50 => "good",
            51..=100 => "moderate",
            101..=150 => "unhealthy for sensitive groups",
            151..=200 => "unhealthy",
            201..=300 => "very unhealthy",
            _ => "hazardous",
        };
        format!("Air: AQI {} ({word})", aqi.round())
    }))
}
