use super::*;

pub(super) fn run_sys_05(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-05", sys_05_body, context, deadline)
}

fn sys_05_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let df = require_tool("df", None)?;
    let scratch = command_scratch(context, "SYS-05")?;

    let mut filesystems: BTreeMap<u64, u64> = BTreeMap::new();
    for path in [Path::new("/"), Path::new("/home")] {
        let device = fs::metadata(path)
            .map(|metadata| metadata.dev())
            .map_err(|error| {
                CheckFailure::fail(
                    "filesystem-inspection-failed",
                    format!(
                        "required filesystem {} could not be inspected: {error}",
                        path.display()
                    ),
                )
            })?;
        let outcome = run_bounded(
            &df,
            &[
                OsString::from("-B1"),
                OsString::from("--output=avail"),
                path.as_os_str().to_owned(),
            ],
            &scratch,
            &context.odin_root,
            deadline,
        )
        .map_err(|error| {
            CheckFailure::fail(
                "free-space-measurement-failed",
                format!("free-space measurement could not execute: {error}"),
            )
        })?;
        if let Some(problem) = command_problem(&outcome) {
            return Err(CheckFailure::fail(
                problem,
                "free-space measurement failed or timed out",
            ));
        }
        let available = parse_last_u64(&outcome.stdout).ok_or_else(|| {
            CheckFailure::fail(
                "df-output-malformed",
                "free-space measurement returned malformed output",
            )
        })?;
        filesystems
            .entry(device)
            .and_modify(|recorded| *recorded = (*recorded).min(available))
            .or_insert(available);
    }
    let free_gib = filesystems
        .values()
        .map(|bytes| (bytes / (1024 * 1024 * 1024)).to_string())
        .collect::<Vec<_>>()
        .join(",");
    note_evidence(&mut evidence, format!("filesystems-free-gib={free_gib}"));

    let nix_db = Path::new("/nix/var/nix/db/db.sqlite");
    let store_size = nix_store_nar_bytes(nix_db, deadline)?;

    let under_floor = filesystems
        .values()
        .any(|available| *available < MIN_FREE_BYTES);
    if under_floor {
        return Err(CheckFailure::fail(
            "storage-floor-breached",
            format!(
                "a distinct backing filesystem has less than {} MiB free (nix store registers {} GiB)",
                MIN_FREE_BYTES / (1024 * 1024),
                store_size / (1024 * 1024 * 1024)
            ),
        ));
    }
    note_evidence(
        &mut evidence,
        format!("nix-store-nar-gib={}", store_size / (1024 * 1024 * 1024)),
    );
    let facts = load_host_facts()?;
    let boot_count = boot_generation_count(Path::new("/boot"));
    let (too_many_boot_generations, boot_metadata_unavailable, boot_skip_note) =
        boot_advisory(facts.as_ref().map(|facts| facts.bootloader), boot_count, 10);
    if let Some(note) = boot_skip_note {
        note_evidence(&mut evidence, note);
    }
    let reasons = advisory_reasons(
        filesystems.values().copied(),
        too_many_boot_generations,
        boot_metadata_unavailable,
    );
    if !reasons.is_empty() {
        return CheckOutcome::flagged(
            reasons.join(","),
            "storage is above the hard floor but has advisory findings",
            evidence,
        );
    }

    CheckOutcome::pass(
        "all distinct backing filesystems exceed 20 GiB free and the Nix store accounting is healthy",
        evidence,
    )
}

/// Free space determines storage health; total store size is evidence, not an absolute limit.
fn advisory_reasons(
    free_bytes: impl IntoIterator<Item = u64>,
    too_many_boot_generations: bool,
    boot_metadata_unavailable: bool,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if free_bytes
        .into_iter()
        .any(|available| available <= CLEAR_FREE_BYTES)
    {
        reasons.push("filesystem-5-to-20-gib");
    }
    if too_many_boot_generations {
        reasons.push("boot-generations-over-10");
    }
    if boot_metadata_unavailable {
        reasons.push("boot-metadata-unavailable");
    }
    reasons
}

/// Reads the aggregate registered NAR size from the Nix store database with a
/// bounded, interruptible query.
fn nix_store_nar_bytes(nix_db: &Path, deadline: Instant) -> Result<u64, CheckFailure> {
    let connection = Connection::open_with_flags(
        nix_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "storage-accounting-database-open-failed",
            format!(
                "Nix store database {} could not be opened read-only: {error}",
                nix_db.display()
            ),
        )
    })?;
    let interrupt_handle = connection.get_interrupt_handle();
    let (sender, receiver) = mpsc::channel::<()>();
    thread::spawn(move || {
        if receiver.recv_timeout(Duration::from_secs(60)).is_err() {
            interrupt_handle.interrupt();
        }
    });
    let query = connection.query_row("SELECT SUM(narSize), COUNT(*) FROM ValidPaths", [], |row| {
        Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?))
    });
    let _ = sender.send(());
    match query {
        Ok((None, 0)) => Ok(0),
        Ok((Some(bytes), _)) => u64::try_from(bytes).map_err(|_| {
            CheckFailure::fail(
                "storage-accounting-invalid-value",
                "Nix store NAR-size accounting returned an invalid byte count",
            )
        }),
        Ok((None, _)) => Err(CheckFailure::fail(
            "storage-accounting-invalid-value",
            "Nix store NAR-size accounting returned no aggregate for registered paths",
        )),
        Err(error) if Instant::now() >= deadline => Err(CheckFailure::fail(
            "storage-accounting-timeout",
            format!("Nix store NAR-size accounting timed out: {error}"),
        )),
        Err(error) => Err(CheckFailure::fail(
            "storage-accounting-query-failed",
            format!("Nix store NAR-size accounting query failed: {error}"),
        )),
    }
}

fn boot_generation_count(root: &Path) -> Option<usize> {
    esp_generation_count(root)
        .or_else(|| profile_generation_count(Path::new("/nix/var/nix/profiles")))
}

/// Profile generation links bound ESP entries when the ESP directory is unreadable.
fn profile_generation_count(profiles: &Path) -> Option<usize> {
    let entries = fs::read_dir(profiles).ok()?;
    Some(
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| {
                name.strip_prefix("system-")
                    .and_then(|rest| rest.strip_suffix("-link"))
                    .is_some_and(|number| number.chars().all(|c| c.is_ascii_digit()))
            })
            .count(),
    )
}

fn esp_generation_count(root: &Path) -> Option<usize> {
    if !root.is_dir() {
        return None;
    }
    let entries = walk_entries(root, 5).ok()?;
    let names = entries
        .iter()
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.file_name().to_str())
        .filter(|name| name.contains("nixos-generation-"))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    Some(names.len())
}

/// The /boot generation advisory inputs for the declared boot layout:
/// (too many generations, metadata unavailable, skip note). The advisory
/// reads the systemd-boot/lanzaboote ESP generation layout; a declared
/// grub-bios or other host keeps kernels in the store and has no /boot
/// generation layout, so the advisory is skipped with an explicit note.
/// Without declared facts the advisory keeps its default-on behavior.
fn boot_advisory(
    bootloader: Option<Bootloader>,
    generation_count: Option<usize>,
    limit: usize,
) -> (bool, bool, Option<String>) {
    match bootloader {
        Some(bootloader @ (Bootloader::GrubBios | Bootloader::Other)) => (
            false,
            false,
            Some(format!(
                "boot-advisory=skipped (the declared {} layout keeps no NixOS generation files in /boot)",
                bootloader.as_str()
            )),
        ),
        _ => (
            generation_count.is_some_and(|count| count > limit),
            generation_count.is_none(),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_generations_count_only_system_links() {
        let root = std::env::temp_dir().join(format!("odin-sweep-profiles-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for name in [
            "system-41-link",
            "system-42-link",
            "system",
            "per-user",
            "system-x-link",
        ] {
            fs::write(root.join(name), b"").unwrap();
        }
        assert_eq!(profile_generation_count(&root), Some(2));
        assert_eq!(profile_generation_count(&root.join("absent")), None);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_boot_advisory_runs_only_for_declared_esp_layouts() {
        // Declared ESP layout: the generation count decides, metadata
        // absence stays a flag reason.
        let (too_many, unavailable, note) =
            boot_advisory(Some(Bootloader::SystemdBoot), Some(11), 10);
        assert!(too_many);
        assert!(!unavailable);
        assert!(note.is_none());
        let (too_many, unavailable, note) = boot_advisory(Some(Bootloader::Lanzaboote), None, 10);
        assert!(!too_many);
        assert!(unavailable, "missing /boot metadata stays honest");
        assert!(note.is_none());

        // Declared BIOS/other layout: the ESP advisory is skipped with an
        // explicit note naming the declared bootloader — even when /boot
        // metadata would be unreadable.
        for bootloader in [Bootloader::GrubBios, Bootloader::Other] {
            let (too_many, unavailable, note) = boot_advisory(Some(bootloader), None, 10);
            assert!(!too_many);
            assert!(!unavailable);
            let note = note.expect("the skip must be recorded");
            assert!(note.contains(bootloader.as_str()), "{note}");
        }
    }

    /// Ten ESP generations pass, eleven flag, and store size alone does not flag a roomy disk.
    #[test]
    fn a_roomy_disk_with_ten_generations_is_clear() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let (ten, _, _) = boot_advisory(Some(Bootloader::SystemdBoot), Some(10), 10);
        assert!(advisory_reasons([1_600 * GIB], ten, false).is_empty());
        let (eleven, _, _) = boot_advisory(Some(Bootloader::SystemdBoot), Some(11), 10);
        assert_eq!(
            advisory_reasons([1_600 * GIB], eleven, false),
            ["boot-generations-over-10"]
        );
        assert_eq!(
            advisory_reasons([1_600 * GIB, 12 * GIB], false, false),
            ["filesystem-5-to-20-gib"]
        );
    }

    #[test]
    fn without_declared_facts_the_boot_advisory_keeps_its_default_on_behavior() {
        let (too_many, unavailable, note) = boot_advisory(None, Some(20), 10);
        assert!(too_many);
        assert!(!unavailable);
        assert!(note.is_none());
        let (_, unavailable, note) = boot_advisory(None, None, 10);
        assert!(unavailable);
        assert!(note.is_none());
    }
}
