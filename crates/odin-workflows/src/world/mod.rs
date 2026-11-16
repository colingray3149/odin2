//! World facts without a web search: weather (with alerts, air and the sun),
//! the time somewhere, public holidays, exchange rates, word definitions,
//! encyclopedia summaries and earthquakes, each one call to a keyless public
//! API. A place is a name, geocoded; no place is home, the declared `home`
//! endpoint (`geo:<lat>,<lon>#<name>`). Answers are cached for ten minutes.

mod facts;
#[cfg(test)]
mod tests;
mod weather;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use url::Url;

use crate::{Ctx, Failure, Workflow};

const CACHE_FOR: Duration = Duration::from_secs(600);

const fn world(
    capability: &'static str,
    run: crate::Run,
    endpoints: &'static [&'static str],
) -> Workflow {
    Workflow {
        capability,
        run,
        plan: None,
        executables: &[],
        roots: &[],
        secrets: &[],
        endpoints,
    }
}

pub const WORKFLOWS: &[Workflow] = &[
    world(
        "world.weather",
        weather::run,
        &[
            "home",
            "open-meteo",
            "open-meteo-geocoding",
            "open-meteo-air",
            "nws",
        ],
    ),
    world(
        "world.time",
        facts::time,
        &["home", "open-meteo", "open-meteo-geocoding"],
    ),
    world("world.holidays", facts::holidays, &["nager"]),
    world("world.fx", facts::fx, &["frankfurter"]),
    world("world.define", facts::define, &["dictionary"]),
    world("world.wiki", facts::wiki, &["wikipedia"]),
    world(
        "world.quake",
        facts::quake,
        &["home", "open-meteo-geocoding", "usgs"],
    ),
];

/// A place by coordinates, its name and (when known) its country code.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Place {
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub country: Option<String>,
}

/// `geo:<lat>,<lon>#<name>`: the declared home.
pub(crate) fn home(url: &Url) -> Result<Place, Failure> {
    let bad = || {
        Failure::unavailable(format!(
            "the home endpoint {url} is not geo:<latitude>,<longitude>#<name>"
        ))
    };
    if url.scheme() != "geo" {
        return Err(bad());
    }
    let (latitude, longitude) = url.path().split_once(',').ok_or_else(bad)?;
    Ok(Place {
        name: url.fragment().unwrap_or("home").replace("%20", " "),
        latitude: latitude.trim().parse().map_err(|_| bad())?,
        longitude: longitude.trim().parse().map_err(|_| bad())?,
        country: Some("US".to_owned()),
    })
}

/// The place named, or home when none is.
pub(crate) fn place(ctx: &Ctx, name: Option<&str>) -> Result<Place, Failure> {
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return home(ctx.endpoint("home")?);
    };
    if ["home", "here"].contains(&name.to_lowercase().as_str()) {
        return home(ctx.endpoint("home")?);
    }
    // "Paris, France" searches better as its first part.
    let query = name.split(',').next().unwrap_or(name).trim();
    let mut url = ctx
        .endpoint("open-meteo-geocoding")?
        .join("v1/search")
        .map_err(join)?;
    url.query_pairs_mut()
        .append_pair("name", query)
        .append_pair("count", "5")
        .append_pair("language", "en");
    let found = get(ctx, &url)?;
    let results = found["results"].as_array().cloned().unwrap_or_default();
    let qualifier = name
        .split_once(',')
        .map(|(_, rest)| rest.trim().to_lowercase());
    let chosen = results
        .iter()
        .find(|result| {
            qualifier.as_ref().is_none_or(|qualifier| {
                ["country", "admin1", "country_code"].iter().any(|key| {
                    result[*key]
                        .as_str()
                        .is_some_and(|value| value.to_lowercase().starts_with(qualifier.as_str()))
                })
            })
        })
        .or(results.first())
        .ok_or_else(|| Failure::arguments(format!("no place called {name:?} was found")))?;
    let label = [&chosen["name"], &chosen["admin1"], &chosen["country"]]
        .iter()
        .filter_map(|part| part.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(Place {
        name: label,
        latitude: chosen["latitude"].as_f64().unwrap_or_default(),
        longitude: chosen["longitude"].as_f64().unwrap_or_default(),
        country: chosen["country_code"].as_str().map(str::to_owned),
    })
}

fn join(error: url::ParseError) -> Failure {
    Failure::unavailable(format!("an endpoint URL could not be built: {error}"))
}

/// One GET of JSON, served from the ten-minute cache when it can be.
pub(crate) fn get(ctx: &Ctx, url: &Url) -> Result<Value, Failure> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    let key = url.to_string();
    if let Some((at, value)) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        if at.elapsed() < CACHE_FOR {
            return Ok(value.clone());
        }
    }
    let host = url.host_str().unwrap_or("the service").to_owned();
    let response = ctx
        .http()?
        .get(url.clone())
        .header("Accept", "application/json, application/geo+json")
        .send()
        .map_err(|error| Failure::upstream(format!("{host} did not answer: {error}")))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(Failure::arguments(format!("{host} has no entry for that")));
    }
    if !status.is_success() {
        return Err(Failure::upstream(format!("{host} answered {status}")));
    }
    let value: Value = response.json().map_err(|error| {
        Failure::upstream(format!("{host} sent something that is not JSON: {error}"))
    })?;
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.retain(|_, (at, _)| at.elapsed() < CACHE_FOR);
    cache.insert(key, (Instant::now(), value.clone()));
    Ok(value)
}

/// An endpoint with a path joined on.
pub(crate) fn endpoint(ctx: &Ctx, key: &str, path: &str) -> Result<Url, Failure> {
    ctx.endpoint(key)?.join(path).map_err(join)
}
