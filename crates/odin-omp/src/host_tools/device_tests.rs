use std::path::PathBuf;

use odin_registry::schema::ProjectSphereToml;

use super::admitted_path;

fn sphere() -> ProjectSphereToml {
    toml::from_str(
        r#"
scratch = "/scratch/project"
[[devices]]
name = "flipper"
node = "/dev/serial/by-id/fixture"
[[devices.actions]]
name = "flash"
argv = ["{runtime.flipper}", "{node}", "flash", "{image}"]
[devices.actions.params]
image = "path"
[[devices.actions]]
name = "read"
argv = ["{runtime.flipper}", "{node}", "read", "{device_path}", "{out}"]
[devices.actions.params]
device_path = "text"
out = "path"
[[devices]]
name = "ring"
endpoint = "unix:///state/device.sock"
[[devices.actions]]
name = "read"
argv = ["{runtime.sensor-read}", "{endpoint}"]
"#,
    )
    .expect("sphere fixture")
}

#[test]
fn a_symlink_out_of_the_scratch_root_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let capsule = root.path().join("capsule");
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&capsule).unwrap();
    std::fs::create_dir(&scratch).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "no").unwrap();
    std::os::unix::fs::symlink(&secret, scratch.join("link")).unwrap();
    let mut declared = sphere();
    declared.scratch = scratch.display().to_string();
    let refused = admitted_path(scratch.join("link").to_str().unwrap(), &capsule, &declared);
    assert!(
        refused.is_err(),
        "a symlink out of the sphere must not join the argv"
    );
}

/// A parent step is refused, but a file name that merely holds two dots is an ordinary name.
#[test]
fn only_a_parent_step_makes_a_path_leave_the_sphere() {
    let root = tempfile::tempdir().unwrap();
    let capsule = root.path().join("capsule");
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&capsule).unwrap();
    std::fs::create_dir(&scratch).unwrap();
    std::fs::write(scratch.join("run..2.png"), "ok").unwrap();
    let mut declared = sphere();
    declared.scratch = scratch.canonicalize().unwrap().display().to_string();
    let inside = scratch.join("run..2.png");
    assert!(admitted_path(inside.to_str().unwrap(), &capsule, &declared).is_ok());
    let climbing = scratch.join("../elsewhere");
    assert!(admitted_path(climbing.to_str().unwrap(), &capsule, &declared).is_err());
}

/// The canonical store path of `name` on the test PATH, if it is one: the
/// bubble mounts the store, not the system profile's symlinks into it.
fn store_tool(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        dir.join(name)
            .canonicalize()
            .ok()
            .filter(|resolved| resolved.starts_with("/nix/store/"))
    })
}

/// One rendered device action really runs inside the lane bubble: its
/// client writes only the sphere's scratch, and `/dev` does not exist in
/// the bubble at all, so no undeclared device node is reachable.
#[test]
fn a_rendered_device_action_runs_confined_with_no_dev() {
    let bwrap = store_tool("bwrap").unwrap_or_else(|| {
        panic!("bwrap is not on PATH as a store tool; run this test inside `nix develop`")
    });
    let bash = store_tool("bash").unwrap_or_else(|| {
        panic!("bash is not on PATH as a store tool; run this test inside `nix develop`")
    });
    let temp = tempfile::tempdir().unwrap();
    let scratch = temp.path().join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let client = temp.path().join("probe-client");
    let script = format!(
        "#!{}\necho \"probe $1\" > \"$2\"\n\
         if test -e /dev; then echo HAS-DEV; else echo NO-DEV; fi\n",
        bash.display(),
    );
    std::fs::write(&client, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = scratch.join("probe.txt");
    let command = vec![
        client.display().to_string(),
        "token".to_owned(),
        out.display().to_string(),
    ];
    let projection = crate::process::SphereProjection {
        data_roots: Vec::new(),
        scratch: scratch.clone(),
        devices: Vec::new(),
        endpoints: Vec::new(),
    };
    let bubble =
        crate::process::capsule_command_argv(temp.path(), &projection, &[], &[], &command).unwrap();
    let output = std::process::Command::new(&bwrap)
        .args(&bubble)
        .output()
        .expect("the bubble runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "NO-DEV");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "probe token\n",);
}
