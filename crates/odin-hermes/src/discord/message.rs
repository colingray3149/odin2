use serde_json::Value;

use super::is_snowflake;

/// One owner-paired Discord message, already projected off the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordMessage {
    pub id: String,
    pub channel_id: String,
    pub author_id: String,
    pub guild_id: Option<String>,
    pub content: String,
    /// Files attached to the message, served from Discord's CDN.
    pub attachments: Vec<DiscordAttachment>,
}

/// One file attached to a message. The URL is confined to Discord's CDN
/// hosts at parse time; nothing else is ever fetched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordAttachment {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub url: String,
    pub content_type: Option<String>,
}

/// The only hosts an attachment URL may name.
const ATTACHMENT_HOSTS: [&str; 2] = ["cdn.discordapp.com", "media.discordapp.net"];

fn parse_attachment(value: &Value) -> Option<DiscordAttachment> {
    let url = value.get("url")?.as_str()?;
    let host = url::Url::parse(url).ok()?;
    if host.scheme() != "https" || !ATTACHMENT_HOSTS.contains(&host.host_str()?) {
        return None;
    }
    let filename = value.get("filename")?.as_str()?;
    if filename.is_empty() || filename.len() > 255 {
        return None;
    }
    Some(DiscordAttachment {
        id: required_snowflake(value.get("id"))?,
        filename: filename.to_owned(),
        size: value.get("size")?.as_u64()?,
        url: url.to_owned(),
        content_type: value
            .get("content_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Parses a real Gateway `MESSAGE_CREATE` dispatch payload (`t == 0` envelope
/// `d` object). Returns `None` for anything that is not a usable channel
/// message; DM messages carry no `guild_id`.
pub fn parse_message_create(payload: &Value) -> Option<DiscordMessage> {
    let id = required_snowflake(payload.get("id"))?;
    let channel_id = required_snowflake(payload.get("channel_id"))?;
    let author = payload.get("author")?;
    let author_id = required_snowflake(author.get("id"))?;
    let guild_id = match payload.get("guild_id") {
        None | Some(Value::Null) => None,
        Some(value) => Some(required_snowflake(Some(value))?),
    };
    let content = match payload.get("content") {
        None => String::new(),
        Some(Value::String(content)) => content.clone(),
        Some(_) => return None,
    };
    let attachments = payload
        .get("attachments")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_attachment).collect())
        .unwrap_or_default();
    Some(DiscordMessage {
        id,
        channel_id,
        author_id,
        guild_id,
        content,
        attachments,
    })
}

fn required_snowflake(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(id)) if is_snowflake(id) => Some(id.clone()),
        _ => None,
    }
}
