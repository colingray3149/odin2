{
  pkgs,
  configFile,
  executables,
  fixtureConfigFile,
  fixturePolicy,
  fixtureProtectedValues,
}:
assert executables ? odind;
let
  entries = pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) executables;

  # The handoff conformance fixture base ships inside the same composition
  # output as the packaged config and runtime manifest. It reuses the parent
  # executable map verbatim and differs from the packaged config in exactly
  # the two browser policy-input paths, which point at the committed
  # fixture bytes copied below. Runtime policy substitution stays guarded:
  # these inputs are selected once, here, at composition build time.
  fixtureDir = "fixtures/odin-07";
  policyPlaceholder = "@odin-fixture-policy@";
  valuesPlaceholder = "@odin-fixture-protected-values@";

  # Parent-manifest binding/compare mechanism. The recorded digests live in
  # fixture-base.json (written by the builder from the actual bytes); this
  # verifier recomputes every digest from file bytes and fails closed on any
  # mismatch, including a fixture base invoked against a foreign composition.
  # Usage: verify-fixture-base <fixture-base-dir> <parent-runtime-manifest>
  verifyFixtureBase = pkgs.writeShellScript "verify-fixture-base" ''
    set -euo pipefail

    jq="${pkgs.jq}/bin/jq"
    b3sum="${pkgs.b3sum}/bin/b3sum"
    diff="${pkgs.diffutils}/bin/diff"
    grep="${pkgs.gnugrep}/bin/grep"

    die() {
      echo "verify-fixture-base: $1" >&2
      exit 1
    }

    digest_of() {
      printf 'blake3:%s' "$("$b3sum" --no-names "$1")"
    }

    if [ "$#" -ne 2 ]; then
      echo "usage: verify-fixture-base <fixture-base-dir> <parent-runtime-manifest>" >&2
      exit 2
    fi
    fixture_base="$1"
    parent_manifest="$2"
    binding="$fixture_base/fixture-base.json"
    fixture_manifest="$fixture_base/runtime-manifest.json"
    fixture_config="$fixture_base/odind.toml"
    policy="$fixture_base/browser-policy.json"
    values="$fixture_base/protected-values.json"

    for file in "$binding" "$parent_manifest" "$fixture_manifest" "$fixture_config" "$policy" "$values"; do
      [ -f "$file" ] || die "required file is missing: $file"
    done

    [ "$("$jq" -r '.schema // empty' "$binding")" = "odin.fixture-base.v1" ] ||
      die "binding schema is not odin.fixture-base.v1"

    # The fixture base belongs to the actual composition output: the recorded
    # parent digest must match the parent manifest it is invoked against.
    [ "$(digest_of "$parent_manifest")" = "$("$jq" -r '.parent_manifest.digest' "$binding")" ] ||
      die "parent manifest digest does not match the recorded composition binding"
    [ "$parent_manifest" = "$("$jq" -r '.parent_manifest.path' "$binding")" ] ||
      die "parent manifest path does not match the recorded composition binding"

    # Parent self-consistency and the strict manifest schema discriminant.
    [ "$("$jq" -r '.schema' "$parent_manifest")" = "odin.runtime-manifest.v1" ] ||
      die "parent manifest schema is not odin.runtime-manifest.v1"
    main_config="$("$jq" -r '.odind_config.path' "$parent_manifest")"
    [ -f "$main_config" ] || die "parent odind config is missing: $main_config"
    [ "$(digest_of "$main_config")" = "$("$jq" -r '.odind_config.digest' "$parent_manifest")" ] ||
      die "parent odind config digest mismatch"

    # The fixture manifest keeps the parent executable map byte for byte.
    [ "$("$jq" -r '.schema' "$fixture_manifest")" = "odin.runtime-manifest.v1" ] ||
      die "fixture manifest schema is not odin.runtime-manifest.v1"
    if ! "$jq" -e -n \
      --slurpfile parent "$parent_manifest" \
      --slurpfile fixture "$fixture_manifest" \
      '($parent[0].executables | to_entries | sort_by(.key))
        == ($fixture[0].executables | to_entries | sort_by(.key))' > /dev/null; then
      die "fixture manifest executable map differs from the parent manifest"
    fi
    while IFS= read -r exe_path; do
      [ -f "$exe_path" ] || die "fixture manifest executable is missing: $exe_path"
    done < <("$jq" -r '.executables[].path' "$fixture_manifest")

    # Fixture manifest, base config, and fixture inputs carry their recorded
    # digests and stay confined to the fixture base directory.
    [ "$(digest_of "$fixture_manifest")" = "$("$jq" -r '.fixture_manifest.digest' "$binding")" ] ||
      die "fixture manifest digest mismatch"
    [ "$fixture_manifest" = "$("$jq" -r '.fixture_manifest.path' "$binding")" ] ||
      die "fixture manifest path does not match the binding"
    for field_path in policy protected_values; do
      recorded="$("$jq" -r --arg field "$field_path" '.[$field].path' "$binding")"
      case "$recorded" in
        "$fixture_base"/*) ;;
        *) die "binding $field_path path escapes the fixture base: $recorded" ;;
      esac
    done

    [ "$(digest_of "$fixture_config")" = "$("$jq" -r '.fixture_config.digest' "$binding")" ] ||
      die "fixture config digest mismatch"
    [ "$fixture_config" = "$("$jq" -r '.odind_config.path' "$fixture_manifest")" ] ||
      die "fixture manifest odind_config does not point at the fixture base config"
    [ "$("$jq" -r '.odind_config.digest' "$fixture_manifest")" = "$("$jq" -r '.fixture_config.digest' "$binding")" ] ||
      die "fixture manifest odind_config digest does not match the binding"
    [ "$(digest_of "$policy")" = "$("$jq" -r '.policy.digest' "$binding")" ] ||
      die "fixture policy digest mismatch"
    [ "$(digest_of "$values")" = "$("$jq" -r '.protected_values.digest' "$binding")" ] ||
      die "fixture protected-values digest mismatch"

    # Only the two policy-input lines may differ between the packaged config
    # and the fixture base config, and both rewrites must target the fixture
    # inputs recorded above.
    diff_out="$("$diff" "$main_config" "$fixture_config" || true)"
    changed_total="$(printf '%s\n' "$diff_out" | "$grep" -c '^[<>] ' || true)"
    [ "$changed_total" = "4" ] ||
      die "fixture config must differ from the packaged config in exactly the two policy-input lines, found $changed_total changed lines"
    main_policy_line="$("$grep" '^policy = "' "$main_config")"
    main_values_line="$("$grep" '^protected_values = "' "$main_config")"
    fixture_policy_line="$("$grep" '^policy = "' "$fixture_config")"
    fixture_values_line="$("$grep" '^protected_values = "' "$fixture_config")"
    printf '%s\n' "$diff_out" | "$grep" -Fqx "< $main_policy_line" ||
      die "packaged policy line was not the replaced policy input"
    printf '%s\n' "$diff_out" | "$grep" -Fqx "< $main_values_line" ||
      die "packaged protected_values line was not the replaced policy input"
    [ "$fixture_policy_line" = "policy = \"$policy\"" ] ||
      die "fixture config policy does not point at the recorded fixture policy"
    [ "$fixture_values_line" = "protected_values = \"$values\"" ] ||
      die "fixture config protected_values does not point at the recorded fixture protected values"

    echo "verify-fixture-base: $fixture_base verified against $parent_manifest"
  '';
in
pkgs.runCommand "odin-home-composition"
  {
    nativeBuildInputs = [
      pkgs.b3sum
      pkgs.jq
      pkgs.diffutils
    ];
  }
  ''
    mkdir -p "$out/bin"
    install -m 0444 ${pkgs.lib.escapeShellArg "${configFile}"} "$out/odind.toml"
    # Mandatory build-time gate: the pinned odind binary strictly parses
    # the exact rendered odind.toml this composition serves (--config-only
    # scope: no registry, state, or network). A dotfiles/binary schema
    # mismatch fails this derivation and every toplevel consuming it.
    ${pkgs.lib.escapeShellArg (toString executables.odind)} check --config-only \
      --config "$out/odind.toml"
    config_digest="blake3:$(b3sum --no-names "$out/odind.toml")"
    jq -n --arg path "$out/odind.toml" --arg digest "$config_digest" \
      '{schema: "odin.runtime-manifest.v1", executables: {}, odind_config: {path: $path, digest: $digest}}' \
      > "$out/runtime-manifest.json"
    ${pkgs.lib.concatMapStringsSep "\n" (entry: ''
      path=${pkgs.lib.escapeShellArg (toString entry.path)}
      test -f "$path"
      test -x "$path"
      ln -s "$path" "$out/bin/${entry.name}"
      digest="blake3:$(b3sum --no-names "$path")"
      jq --arg key ${pkgs.lib.escapeShellArg entry.name} --arg path "$path" --arg digest "$digest" \
        '.executables[$key] = {path: $path, digest: $digest}' \
        "$out/runtime-manifest.json" > "$out/runtime-manifest.next"
      mv "$out/runtime-manifest.next" "$out/runtime-manifest.json"
    '') entries}

    # Unswitched candidate entrypoint: bind the exact composed manifest and
    # config before starting the packaged daemon. Runtime-private policy,
    # authority, device, and registry publication material stays outside this
    # immutable closure and is provisioned by the operator-facing candidate.
    cat > "$out/bin/odind-candidate" <<EOF
    #!${pkgs.runtimeShell}
    set -euo pipefail
    export ODIN_RUNTIME_MANIFEST="$out/runtime-manifest.json"
    exec "$out/bin/odind" huginn --config "$out/odind.toml" "\$@"
    EOF
    chmod 0555 "$out/bin/odind-candidate"

    launcher_digest="blake3:$(b3sum --no-names "$out/bin/odind-candidate")"
    manifest_digest="blake3:$(b3sum --no-names "$out/runtime-manifest.json")"
    jq -n \
      --arg launcher_path "$out/bin/odind-candidate" \
      --arg launcher_digest "$launcher_digest" \
      --arg manifest_path "$out/runtime-manifest.json" \
      --arg manifest_digest "$manifest_digest" \
      --arg config_path "$out/odind.toml" \
      --arg config_digest "$config_digest" \
      '{
        schema: "odin.candidate-composition.v1",
        launcher: {path: $launcher_path, digest: $launcher_digest},
        runtime_manifest: {path: $manifest_path, digest: $manifest_digest},
        odind_config: {path: $config_path, digest: $config_digest}
      }' > "$out/candidate.json"

    # Handoff conformance fixture base: committed synthetic browser policy
    # and protected-value bytes plus a derived base config whose only
    # differences from the packaged config are the two policy-input paths.
    fixture_dir="$out/${fixtureDir}"
    mkdir -p "$fixture_dir"

    fixture_policy="$fixture_dir/browser-policy.json"
    fixture_values="$fixture_dir/protected-values.json"
    install -m 0444 ${pkgs.lib.escapeShellArg "${fixturePolicy}"} "$fixture_policy"
    install -m 0444 ${pkgs.lib.escapeShellArg "${fixtureProtectedValues}"} "$fixture_values"
    cmp ${pkgs.lib.escapeShellArg "${fixturePolicy}"} "$fixture_policy"
    cmp ${pkgs.lib.escapeShellArg "${fixtureProtectedValues}"} "$fixture_values"

    install -m 0444 ${pkgs.lib.escapeShellArg "${fixtureConfigFile}"} "$fixture_dir/odind.toml"
    sed -i "s|${policyPlaceholder}|$fixture_policy|g; s|${valuesPlaceholder}|$fixture_values|g" "$fixture_dir/odind.toml"
    chmod 0444 "$fixture_dir/odind.toml"
    if grep -q -e '${policyPlaceholder}' -e '${valuesPlaceholder}' "$fixture_dir/odind.toml"; then
      echo "fixture config still contains unresolved placeholders" >&2
      exit 1
    fi

    diff_out="$(diff "$out/odind.toml" "$fixture_dir/odind.toml" || true)"
    changed_total="$(printf '%s\n' "$diff_out" | grep -c '^[<>] ' || true)"
    if [ "$changed_total" != "4" ] \
      || [ "$(printf '%s\n' "$diff_out" | grep -c '^< policy = "' || true)" != "1" ] \
      || [ "$(printf '%s\n' "$diff_out" | grep -c '^< protected_values = "' || true)" != "1" ] \
      || [ "$(printf '%s\n' "$diff_out" | grep -c '^> policy = "' || true)" != "1" ] \
      || [ "$(printf '%s\n' "$diff_out" | grep -c '^> protected_values = "' || true)" != "1" ]; then
      echo "fixture config must differ from the packaged config in exactly the two policy-input lines" >&2
      exit 1
    fi

    fixture_config_digest="blake3:$(b3sum --no-names "$fixture_dir/odind.toml")"
    policy_digest="blake3:$(b3sum --no-names "$fixture_policy")"
    values_digest="blake3:$(b3sum --no-names "$fixture_values")"
    parent_manifest_digest="blake3:$(b3sum --no-names "$out/runtime-manifest.json")"

    jq --arg path "$fixture_dir/odind.toml" --arg digest "$fixture_config_digest" \
      '. + {odind_config: {path: $path, digest: $digest}}' \
      "$out/runtime-manifest.json" > "$fixture_dir/runtime-manifest.json"
    fixture_manifest_digest="blake3:$(b3sum --no-names "$fixture_dir/runtime-manifest.json")"

    jq -n \
      --arg comp "$out" \
      --arg root "$fixture_dir" \
      --arg parent_path "$out/runtime-manifest.json" \
      --arg parent_digest "$parent_manifest_digest" \
      --arg manifest_path "$fixture_dir/runtime-manifest.json" \
      --arg manifest_digest "$fixture_manifest_digest" \
      --arg config_path "$fixture_dir/odind.toml" \
      --arg config_digest "$fixture_config_digest" \
      --arg policy_path "$fixture_policy" \
      --arg policy_digest "$policy_digest" \
      --arg values_path "$fixture_values" \
      --arg values_digest "$values_digest" \
      '{
        schema: "odin.fixture-base.v1",
        composition_root: $comp,
        fixture_root: $root,
        parent_manifest: {path: $parent_path, digest: $parent_digest},
        fixture_manifest: {path: $manifest_path, digest: $manifest_digest},
        fixture_config: {path: $config_path, digest: $config_digest},
        policy: {path: $policy_path, digest: $policy_digest},
        protected_values: {path: $values_path, digest: $values_digest}
      }' > "$fixture_dir/fixture-base.json"

    install -m 0555 ${verifyFixtureBase} "$fixture_dir/verify-fixture-base"

    echo "odin-07 fixture base: $fixture_dir"
    echo "fixture policy: $policy_digest"
    echo "fixture protected values: $values_digest"
    echo "fixture config: $fixture_config_digest"
    echo "fixture manifest: $fixture_manifest_digest"
    echo "parent manifest binding: $parent_manifest_digest"
  ''
