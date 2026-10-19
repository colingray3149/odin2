use super::*;

use std::path::Path;

#[test]
fn config_required_for_every_production_constructor() {
    use clap::CommandFactory as _;
    assert!(Cli::command()
        .try_get_matches_from(["odind", "check"])
        .is_err());
    assert!(Cli::command()
        .try_get_matches_from(["odind", "huginn"])
        .is_err());
    assert!(load_config(Path::new("/nonexistent/odind.toml")).is_err());
    assert!(Cli::command()
        .try_get_matches_from(["odind", "huginn", "--config", "c", "--seat-binding", "{}"])
        .is_err());
}

#[test]
fn check_config_only_accepts_a_strict_config_without_registry_or_state() {
    use clap::Parser as _;
    let fixture = tempfile::TempDir::new().expect("temporary directory");
    let config_path = fixture.path().join("odind.toml");
    std::fs::write(
        &config_path,
        crate::test_fixture::fixture_config_text(
            fixture.path(),
            &fixture.path().join("snapshot.json"),
        ),
    )
    .expect("write fixture config");
    // Leave declared paths absent to catch accidental registry or state access.
    run(Cli::parse_from([
        "odind",
        "check",
        "--config-only",
        "--config",
        config_path.to_str().expect("utf-8 config path"),
    ]))
    .expect("config-only check succeeds without registry or state");
}

#[test]
fn check_config_only_refuses_a_rendered_discord_surface_missing_project() {
    use clap::Parser as _;
    let fixture = tempfile::TempDir::new().expect("temporary directory");
    let config_path = fixture.path().join("odind.toml");
    let mut text = crate::test_fixture::fixture_config_text(
        fixture.path(),
        &fixture.path().join("snapshot.json"),
    );
    text.push_str(&format!(
        "[hermes]\nstate_dir = '{0}/state/hermes'\n[hermes.discord]\n\
         seat = 'coordinator'\nproject = 'life'\nowner_user_id = 'owner'\n\
         notify_channel_id = 'paired-channel'\ncapability = 'discord.intake'\n\
         egress_capacity = 8\ngateway_intents = 1\n\
         bot_token_handle = 'cred:discord.bot'\nttl_seconds = 300\n",
        fixture.path().display(),
    ));
    std::fs::write(&config_path, &text).expect("write fixture config");
    run(Cli::parse_from([
        "odind",
        "check",
        "--config-only",
        "--config",
        config_path.to_str().expect("utf-8 config path"),
    ]))
    .expect("the rendered discord surface parses and validates");
    // Remove only the Discord project; other project fields must not satisfy it.
    let mut table: toml::Table = text.parse().expect("fixture config parses as toml");
    table
        .get_mut("hermes")
        .expect("hermes section")
        .as_table_mut()
        .expect("hermes table")
        .get_mut("discord")
        .expect("discord section")
        .as_table_mut()
        .expect("discord table")
        .remove("project")
        .expect("discord project present");
    let missing_project = toml::to_string(&table).expect("serializes");
    std::fs::write(&config_path, missing_project).expect("rewrite fixture config");
    let error = run(Cli::parse_from([
        "odind",
        "check",
        "--config-only",
        "--config",
        config_path.to_str().expect("utf-8 config path"),
    ]))
    .expect_err("a rendered [hermes.discord] without project must refuse");
    assert!(
        error.contains("project"),
        "the refusal must name the missing field: {error}"
    );
}
