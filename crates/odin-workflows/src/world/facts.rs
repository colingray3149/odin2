//! The other world facts: the time somewhere, holidays, exchange rates,
//! definitions, encyclopedia summaries and earthquakes.

use serde_json::{json, Value};
use time::OffsetDateTime;

use super::{endpoint, get, place, Place};
use crate::{args, Call, Ctx, Failure};

/// The local clock at a place: its time zone and offset from Open-Meteo.
fn clock(ctx: &Ctx, place: &Place) -> Result<(String, String, i64), Failure> {
    let mut url = endpoint(ctx, "open-meteo", "v1/forecast")?;
    url.query_pairs_mut()
        .append_pair("latitude", &place.latitude.to_string())
        .append_pair("longitude", &place.longitude.to_string())
        .append_pair("current", "is_day")
        .append_pair("timezone", "auto")
        .append_pair("forecast_days", "1");
    // Only the zone and offset are used, so a cached answer is still right.
    let found = get(ctx, &url)?;
    let zone = found["timezone"].as_str().unwrap_or("UTC").to_owned();
    let abbreviation = found["timezone_abbreviation"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let offset = found["utc_offset_seconds"].as_i64().unwrap_or(0);
    Ok((zone, abbreviation, offset))
}

fn offset_text(seconds: i64) -> String {
    let sign = if seconds < 0 { '-' } else { '+' };
    let minutes = seconds.abs() / 60;
    match minutes % 60 {
        0 => format!("UTC{sign}{}", minutes / 60),
        rest => format!("UTC{sign}{}:{rest:02}", minutes / 60),
    }
}

pub fn time(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let there = place(ctx, args::opt_str(input, "place"))?;
    let (zone, abbreviation, offset) = clock(ctx, &there)?;
    let now = OffsetDateTime::now_utc();
    let local = now + time::Duration::seconds(offset);
    let shown = format!(
        "{:02}:{:02} {} {} {}",
        local.hour(),
        local.minute(),
        local.weekday(),
        local.month(),
        local.day()
    );
    let mut line = format!(
        "{}: {shown} ({}{})",
        there.name,
        if abbreviation.is_empty() {
            String::new()
        } else {
            format!("{abbreviation}, ")
        },
        offset_text(offset)
    );
    let home = super::home(ctx.endpoint("home")?)?;
    if home != there {
        let (_, _, home_offset) = clock(ctx, &home)?;
        let hours = (offset - home_offset) as f64 / 3600.0;
        if hours != 0.0 {
            let ahead = if hours > 0.0 { "ahead of" } else { "behind" };
            line.push_str(&format!("; {} h {ahead} {}", hours.abs(), home.name));
        }
    }
    Ok(json!({"done": line, "place": there.name, "timeZone": zone, "utcOffsetSeconds": offset}))
}

pub fn holidays(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let country = args::opt_str(input, "country")
        .unwrap_or("US")
        .trim()
        .to_uppercase();
    let today = OffsetDateTime::now_utc().date();
    let year = args::opt_u64(input, "year").unwrap_or(today.year() as u64);
    let url = endpoint(
        ctx,
        "nager",
        &format!("api/v3/PublicHolidays/{year}/{country}"),
    )?;
    let found = get(ctx, &url)?;
    let all: Vec<(String, String)> = found
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|day| {
            Some((
                day["date"].as_str()?.to_owned(),
                day["name"]
                    .as_str()
                    .or(day["localName"].as_str())?
                    .to_owned(),
            ))
        })
        .collect();
    let today = today.to_string();
    let shown: Vec<&(String, String)> = if args::opt_u64(input, "year").is_some() {
        all.iter().collect()
    } else {
        all.iter()
            .filter(|(date, _)| *date >= today)
            .take(6)
            .collect()
    };
    if shown.is_empty() {
        return Ok(
            json!({"done": format!("No public holidays left in {year} for {country}."), "holidays": []}),
        );
    }
    let lines: Vec<String> = shown
        .iter()
        .map(|(date, name)| format!("{date} {name}"))
        .collect();
    Ok(json!({
        "done": format!("Public holidays ({country}):\n{}", lines.join("\n")),
        "holidays": shown.iter().map(|(date, name)| json!({"date": date, "name": name})).collect::<Vec<_>>(),
    }))
}

pub fn fx(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let from = args::opt_str(input, "from")
        .unwrap_or("USD")
        .trim()
        .to_uppercase();
    let to = args::str(input, "to")?.replace(' ', "").to_uppercase();
    let amount = input.get("amount").and_then(Value::as_f64).unwrap_or(1.0);
    let mut url = endpoint(ctx, "frankfurter", "v1/latest")?;
    url.query_pairs_mut()
        .append_pair("base", &from)
        .append_pair("symbols", &to)
        .append_pair("amount", &amount.to_string());
    let found = get(ctx, &url)?;
    let rates = found["rates"].as_object().cloned().unwrap_or_default();
    if rates.is_empty() {
        return Err(Failure::arguments(format!(
            "no rate from {from} to {to}; currencies are ISO codes such as USD, EUR, JPY"
        )));
    }
    let lines: Vec<String> = rates
        .iter()
        .map(|(currency, value)| {
            format!(
                "{amount} {from} = {} {currency}",
                value
                    .as_f64()
                    .map_or(String::new(), |value| format!("{value:.2}"))
            )
        })
        .collect();
    Ok(json!({
        "done": format!("{} (ECB rate of {})", lines.join("; "), found["date"].as_str().unwrap_or("today")),
        "rates": rates,
    }))
}

pub fn define(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let word = args::str(input, "word")?.trim().to_lowercase();
    let mut url = endpoint(ctx, "dictionary", "api/v2/entries/en/")?;
    url.path_segments_mut()
        .map_err(|()| Failure::unavailable("the dictionary endpoint cannot take a path"))?
        .pop_if_empty()
        .push(&word);
    let found = get(ctx, &url).map_err(|failure| {
        Failure::arguments(format!("no definition of {word:?}: {}", failure.cause))
    })?;
    let entry = &found[0];
    let mut lines = vec![match entry["phonetic"].as_str() {
        Some(sound) => format!("{word} {sound}"),
        None => word.clone(),
    }];
    for meaning in entry["meanings"].as_array().into_iter().flatten().take(3) {
        let part = meaning["partOfSpeech"].as_str().unwrap_or("");
        for definition in meaning["definitions"]
            .as_array()
            .into_iter()
            .flatten()
            .take(2)
        {
            let Some(text) = definition["definition"].as_str() else {
                continue;
            };
            let mut line = format!("({part}) {text}");
            if let Some(example) = definition["example"].as_str() {
                line.push_str(&format!(" — \"{example}\""));
            }
            lines.push(line);
        }
    }
    Ok(json!({"done": lines.join("\n"), "word": word}))
}

pub fn wiki(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let title = args::str(input, "title")?.trim().to_owned();
    let mut url = endpoint(ctx, "wikipedia", "w/api.php")?;
    // The best search hit, its lead section as plain text, redirects followed.
    url.query_pairs_mut()
        .append_pair("action", "query")
        .append_pair("format", "json")
        .append_pair("formatversion", "2")
        .append_pair("generator", "search")
        .append_pair("gsrsearch", &title)
        .append_pair("gsrlimit", "1")
        .append_pair("prop", "extracts|info")
        .append_pair("exintro", "1")
        .append_pair("explaintext", "1")
        .append_pair("exsentences", "5")
        .append_pair("inprop", "url")
        .append_pair("redirects", "1");
    let found = get(ctx, &url)?;
    let page = found["query"]["pages"]
        .get(0)
        .ok_or_else(|| Failure::arguments(format!("Wikipedia has no article for {title:?}")))?;
    let name = page["title"].as_str().unwrap_or(&title);
    let extract = page["extract"].as_str().unwrap_or("").trim();
    let link = page["fullurl"].as_str().unwrap_or("");
    Ok(json!({"done": format!("{name}: {extract}\n{link}"), "title": name, "url": link}))
}

pub fn quake(ctx: &Ctx, _call: &Call, input: &Value) -> Result<Value, Failure> {
    let near = place(ctx, args::opt_str(input, "place"))?;
    let radius = args::opt_u64(input, "radius_km")
        .unwrap_or(300)
        .clamp(10, 5000);
    let days = args::opt_u64(input, "days").unwrap_or(7).clamp(1, 90);
    let minimum = input
        .get("min_magnitude")
        .and_then(Value::as_f64)
        .unwrap_or(2.5);
    let since = (OffsetDateTime::now_utc() - time::Duration::days(days as i64)).date();
    let mut url = endpoint(ctx, "usgs", "fdsnws/event/1/query")?;
    url.query_pairs_mut()
        .append_pair("format", "geojson")
        .append_pair("latitude", &near.latitude.to_string())
        .append_pair("longitude", &near.longitude.to_string())
        .append_pair("maxradiuskm", &radius.to_string())
        .append_pair("starttime", &since.to_string())
        .append_pair("minmagnitude", &minimum.to_string())
        .append_pair("orderby", "time")
        .append_pair("limit", "10");
    let found = get(ctx, &url)?;
    let lines: Vec<String> = found["features"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|feature| {
            let properties = &feature["properties"];
            let magnitude = properties["mag"].as_f64()?;
            let at = properties["time"]
                .as_i64()
                .and_then(|ms| OffsetDateTime::from_unix_timestamp(ms / 1000).ok())
                .map(|at| format!("{} {:02}:{:02} UTC", at.date(), at.hour(), at.minute()))
                .unwrap_or_default();
            Some(format!(
                "M{magnitude:.1} {} — {at}",
                properties["place"].as_str().unwrap_or("?")
            ))
        })
        .collect();
    let done = if lines.is_empty() {
        format!("No earthquakes of M{minimum} or more within {radius} km of {} in the last {days} days.", near.name)
    } else {
        format!(
            "Earthquakes of M{minimum}+ within {radius} km of {} in the last {days} days, newest first:\n{}",
            near.name,
            lines.join("\n")
        )
    };
    Ok(json!({"done": done, "count": lines.len()}))
}
