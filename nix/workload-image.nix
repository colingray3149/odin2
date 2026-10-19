# Confined workload-environment OCI image.
#
# Two modes:
#
# 1. Normalize mode (`dockerArchive` given): a self-contained docker/OCI
#    archive is an immutable build input. The
#    wrapper rejects any input that is not exactly one single-layer
#    image manifest (the shape mode 2 emits: a multi-manifest index or
#    a multi-layer manifest would be preserved by reference but only
#    partially repacked), validates every blob and every embedded tool
#    INSIDE the archive with image-root semantics, repacks it
#    deterministically as an OCI layout, and derives identity.json from
#    the PRESERVED manifest bytes. The digest pin holds on every node
#    that imports the archive — no per-importer synthesis.
# 2. From-source mode (default): builds the image from the pinned stock
#    OMP launcher, the odin/odind binaries whose browser arm embeds the
#    Playwright worker, the pinned shared harness extension module
#    (odin-extension shipped under /odin/lib/odin-extension), and the
#    browser display mechanism (Chromium, Xvfb) with real runtime
#    dependencies, then emits the same output shape with a canonical
#    manifest constructed from its own blob digests.
#
# Nothing about seats, models, policy, credentials, or host paths is baked
# in; /state and /export are runtime-declared mounts.
{
  pkgs,
  lib,
  # From-source mode inputs.
  ompStock ? null,
  odinBin ? null,
  # The pinned shared harness extension derivation (flake
  # packages.odin-extension): from-source mode ships it verbatim under
  # /odin/lib/odin-extension and records the entry file's blake3 in the
  # image identity tools map. Normalize mode instead requires the
  # extension entry inside the input archive.
  odinExtension ? null,
  # Claude Code itself: the claude.* workload driver runs the pinned CLI
  # (-p, stream-json) in the governed pod. Unfree in nixpkgs, so the flake
  # passes the package from an instance that allows exactly it.
  claudeCode ? null,
  sourceRevision ? "unknown",
  # Shared identity inputs.
  ompRevision ? "unknown",
  # Normalize mode requires an immutable store path to a self-contained image archive.
  dockerArchive ? null,
}:
let
  tarFlags = "--sort=name --mtime=@0 --owner=0 --group=0";

  # Provenance alias: the caller's git revision when one exists;
  # otherwise the ACTUAL odin derivation hash, which names the exact
  # filtered dirty-source build (a bare HEAD would misattribute the built
  # bytes). Never empty and never "unknown" — the image identity must
  # always name real bytes or the build fails closed.
  odinDrvHash =
    if odinBin == null then ""
    else builtins.substring 0 32 (builtins.baseNameOf (toString odinBin));
  revisionAlias =
    if sourceRevision != "unknown" && sourceRevision != "" then sourceRevision
    else if odinDrvHash != "" then odinDrvHash
    else builtins.throw "workload-image: no source revision and no odin derivation identity — refusing empty provenance";

  # Shared identity emitter; the caller sets the shell variables it reads.
  identityJson = ''
    jq -n \
      --arg schema "odin.workload-image-identity.v1" \
      --arg image_name "$image_name" \
      --arg tag "$tag" \
      --arg manifest_digest "$manifest_digest" \
      --arg config_digest "$config_digest" \
      --arg archive_sha256 "$archive_sha256" \
      --arg omp_source_revision "${toString ompRevision}" \
      --arg source_revision "${revisionAlias}" \
      --arg import_archive "$import_archive" \
      --argjson tools "$tools_json" \
      --argjson module_roots "$module_roots_json" \
      --argjson image_config "$image_config_json" \
      '{
        schema: $schema,
        reference: ($image_name + "@" + $manifest_digest),
        image_name: $image_name,
        tag: $tag,
        manifest_digest: $manifest_digest,
        config_digest: $config_digest,
        import_archive: $import_archive,
        omp_source_revision: $omp_source_revision,
        archive_sha256: $archive_sha256,
        source_revision: $source_revision,
        tools: $tools,
        module_roots: $module_roots,
        mount_points: ["/state", "/export"],
        config: $image_config
      }' > "$out/identity.json"
  '';

  # Validate tool links and required image files without resolving through the host filesystem.
  # Runtime dependency availability still requires a nonroot launcher/browser smoke run.
  inImageValidation = ''
      for tool in omp odin odind node chromium Xvfb mcp-server-filesystem; do
        test -L "$image_root/odin/bin/$tool" || {
          echo "missing tool link: $tool" >&2
          exit 1
        }
      done

      # Root-relative component resolution with the plain shell stdlib:
      # every path component is resolved HERE, against the extraction
      # root — absolute link targets are re-rooted, ".." is popped
      # lexically, and no kernel lookup ever walks an unverified
      # component, so nothing can resolve through the host filesystem.
      # Echoes the final in-image path; fails closed if anything escapes
      # the root, loops, or is missing inside the image.
      resolve_in_image() {
        local in_path="$1" cur="" rest hops=0 comp candidate target
        rest="$in_path/"
        while test -n "$rest"; do
          comp="''${rest%%/*}"
          rest="''${rest#*/}"
          if test "$comp" = "" -o "$comp" = "."; then
            continue
          fi
          if test "$comp" = ".."; then
            case "$cur" in
              "") echo "path escapes image root: $in_path" >&2; exit 1 ;;
              *) cur="''${cur%/*}" ;;
            esac
            continue
          fi
          candidate="$image_root$cur/$comp"
          if test -L "$candidate"; then
            target="$(readlink "$candidate")" || {
              echo "unreadable link: $candidate" >&2
              exit 1
            }
            hops=$((hops + 1))
            if test "$hops" -ge 64; then
              echo "symlink loop while resolving: $in_path" >&2
              exit 1
            fi
            case "$target" in
              /*) cur="" ;;
            esac
            rest="$target/$rest"
          else
            cur="$cur/$comp"
          fi
        done
        test -e "$image_root$cur" || {
          echo "target missing inside image: $in_path -> $cur" >&2
          exit 1
        }
        printf '%s\n' "$cur"
      }

      # blake3 of one in-image target, computed as an explicitly checked
      # statement: a failed, empty, or malformed hash rejects the build
      # before any JSON is emitted. (Runtime dependency closure is a
      # property of the Nix closure that from-source mode packs in, and
      # is proven by the real launcher/browser smoke — never asserted
      # here.)
      tool_hash() {
        hash="$(b3sum --no-names "$image_root$1")" || {
          echo "workload image: hashing failed: $1" >&2
          exit 1
        }
        if ! [[ "$hash" =~ ^[0-9a-f]{64}$ ]]; then
          echo "workload image: empty or malformed blake3 for $1: '$hash'" >&2
          exit 1
        fi
      }

      omp_target="$(resolve_in_image /odin/bin/omp)" || exit 1
      odin_target="$(resolve_in_image /odin/bin/odin)" || exit 1
      odind_target="$(resolve_in_image /odin/bin/odind)" || exit 1
      node_target="$(resolve_in_image /odin/bin/node)" || exit 1
      chromium_target="$(resolve_in_image /odin/bin/chromium)" || exit 1
      xvfb_target="$(resolve_in_image /odin/bin/Xvfb)" || exit 1
      playwright_target="$(resolve_in_image /odin/lib/playwright-core)" || exit 1
      extension_dir_target="$(resolve_in_image /odin/lib/odin-extension)" || exit 1
      extension_target="$(resolve_in_image /odin/lib/odin-extension/index.ts)" || exit 1
      cacert_target="$(resolve_in_image /etc/ssl/certs/ca-certificates.crt)" || exit 1
      fonts_target="$(resolve_in_image /odin/etc/fonts.conf)" || exit 1
      # Generic exec-transport mechanism: the kube exec carrier prefixes
      # pinned launcher argv with /bin/env (coreutils), so its in-image
      # presence is validated exactly like the declared tools. Transport
      # constant only — never a profile field, never in identity.json.
      env_target="$(resolve_in_image /bin/env)" || exit 1
      filesystem_target="$(resolve_in_image /odin/bin/mcp-server-filesystem)" || exit 1
      python_target="$(resolve_in_image /bin/python3)" || exit 1
      git_target="$(resolve_in_image /bin/git)" || exit 1
      for target in "$filesystem_target" "$python_target" "$git_target"; do
        test -f "$image_root$target" || {
          echo "Claude driver dependency is not a regular file: $target" >&2
          exit 1
        }
      done
      test -f "$image_root$env_target" || {
        echo "env target not a regular file: $env_target" >&2
        exit 1
      }
      test -d "$image_root$playwright_target" || {
        echo "playwright module target not a directory: $playwright_target" >&2
        exit 1
      }
      test -d "$image_root$extension_dir_target" || {
        echo "extension module target not a directory: $extension_dir_target" >&2
        exit 1
      }
      test -f "$image_root$extension_target" || {
        echo "extension entry target not a regular file: $extension_target" >&2
        exit 1
      }
      test -s "$image_root$extension_target" || {
        echo "extension entry target empty: $extension_target" >&2
        exit 1
      }
      # Nonroot readability law: the image runs as 65534:65534 while the
      # embedded store bytes are root-owned, so every extension module
      # file must be other-readable and every module directory
      # other-traversable — a mode slip would strand the nonroot runtime
      # mid-launch with an unreadable trusted extension.
      unreadable="$(find "$image_root$extension_dir_target" -type f \( ! -perm -0004 -o -empty \) -print -quit)" || {
        echo "workload image: extension module readability scan failed" >&2
        exit 1
      }
      test -z "$unreadable" || {
        echo "extension module file unreadable or empty for nonroot runtime: $unreadable" >&2
        exit 1
      }
      untraversable="$(find "$image_root$extension_dir_target" -type d ! -perm -0001 -print -quit)" || {
        echo "workload image: extension module traversal scan failed" >&2
        exit 1
      }
      test -z "$untraversable" || {
        echo "extension module directory not traversable by nonroot user: $untraversable" >&2
        exit 1
      }
      test -f "$image_root$cacert_target" || {
        echo "cacert target not a regular file: $cacert_target" >&2
        exit 1
      }
      test -f "$image_root$fonts_target" || {
        echo "fonts.conf target not a regular file: $fonts_target" >&2
        exit 1
      }
      for target in "$omp_target" "$odin_target" "$odind_target" \
        "$node_target" "$chromium_target" "$xvfb_target"; do
        test -f "$image_root$target" || {
          echo "tool target not a regular file: $target" >&2
          exit 1
        }
      done

      # The workload carrier's PID1 is composed from the identity's own
      # declared odind entrypoint (the same in-image bytes the host-side
      # exec transport launches later, see odin-cli
      # src/odind/workload_park.rs and kube_runtime/launch.rs): every
      # workload pod execs that exact target as 65534:65534 with all
      # capabilities dropped, so it must be an executable regular file. A
      # mode slip would strand every carrier at pod start instead of
      # parking it — the unpacking validation must fail closed on it here,
      # not at run time.
      test -x "$image_root$odind_target" || {
        echo "carrier mechanism target not executable: $odind_target" >&2
        exit 1
      }

      tool_hash "$omp_target"; omp_hash="$hash"
      tool_hash "$odin_target"; odin_hash="$hash"
      tool_hash "$odind_target"; odind_hash="$hash"
      tool_hash "$node_target"; node_hash="$hash"
      tool_hash "$chromium_target"; chromium_hash="$hash"
      tool_hash "$xvfb_target"; xvfb_hash="$hash"
      tool_hash "$extension_target"; extension_hash="$hash"
  '';

  # Shared per-tool identity emitter; requires image_root and the
  # omp_target .. xvfb_target / extension_target variables that
  # inImageValidation sets to resolved IN-IMAGE paths.
  identitiesJson = ''
      # Per-tool identity: blake3 of the resolved in-image target bytes;
      # store identities are in-image store paths, never host or
      # build-directory paths. tool_hash already rejected any empty or
      # failed hash, so a dangling target can never reach identity.json.
      # tools.extension is the trusted harness extension entry: admission
      # compares its blake3 with the composed extension policy digest and
      # the remote spec binds in_image as the launcher's extension path.
      tools_json="$(jq -n \
        --arg omp_target "$omp_target" --arg omp "$omp_hash" \
        --arg odin_target "$odin_target" --arg odin "$odin_hash" \
        --arg odind_target "$odind_target" --arg odind "$odind_hash" \
        --arg node_target "$node_target" --arg node "$node_hash" \
        --arg chromium_target "$chromium_target" --arg chromium "$chromium_hash" \
        --arg xvfb_target "$xvfb_target" --arg xvfb "$xvfb_hash" \
        --arg extension_target "$extension_target" --arg extension "$extension_hash" \
        '{
          omp:      {in_image: "/odin/bin/omp",      store: $omp_target,      blake3: ("blake3:" + $omp)},
          odin:     {in_image: "/odin/bin/odin",     store: $odin_target,     blake3: ("blake3:" + $odin)},
          odind:    {in_image: "/odin/bin/odind",    store: $odind_target,    blake3: ("blake3:" + $odind)},
          node:     {in_image: "/odin/bin/node",     store: $node_target,     blake3: ("blake3:" + $node)},
          chromium: {in_image: "/odin/bin/chromium", store: $chromium_target, blake3: ("blake3:" + $chromium)},
          xvfb:     {in_image: "/odin/bin/Xvfb",     store: $xvfb_target,     blake3: ("blake3:" + $xvfb)},
          extension: {in_image: "/odin/lib/odin-extension/index.ts", store: $extension_target, blake3: ("blake3:" + $extension)}
        }')" || exit 1
      module_roots_json="$(jq -n \
        --arg playwright_target "$playwright_target" \
        '{
          playwright: {in_image: "/odin/lib/playwright-core", store: $playwright_target}
        }')" || exit 1
      test -n "$tools_json" || { echo "workload image: tools identity JSON emission failed" >&2; exit 1; }
      test -n "$module_roots_json" || { echo "workload image: module identity JSON emission failed" >&2; exit 1; }
  '';
in
if dockerArchive != null then
  pkgs.runCommand "odin-workload-image"
    {
      nativeBuildInputs = [
        pkgs.b3sum
        pkgs.coreutils
        pkgs.findutils
        pkgs.jq
      ];
    }
    ''
      mkdir -p "$out" "$PWD/.work/docker" "$PWD/.work/oci/blobs/sha256" "$PWD/.work/root"
      tar -xf "${dockerArchive}" -C "$PWD/.work/docker"

      index="$PWD/.work/docker/index.json"
      # Fail closed: the governed digest reference must be declarable.
      # The from-source mode annotates its index with
      # io.containerd.image.name = image@manifest_digest and this builder
      # preserves that annotation verbatim; an input without it could
      # never register the governed reference on import.
      jq -e '.manifests[0].annotations["io.containerd.image.name"]' "$index" >/dev/null || {
        echo "unsupported input: preserved index declares no io.containerd.image.name annotation" >&2
        exit 1
      }

      require_sha256() {
        case "$1" in
          sha256:*) ;;
          *)
            echo "unsupported input: expected a sha256:... digest, got '$1'" >&2
            exit 1
            ;;
        esac
        if ! [[ "''${1#sha256:}" =~ ^[0-9a-f]{64}$ ]]; then
          echo "unsupported input: malformed sha256 digest '$1'" >&2
          exit 1
        fi
      }
      # Fail closed: the supported input is exactly ONE single-layer
      # image manifest. The whole index and manifest are preserved
      # verbatim below; anything beyond one manifest (attestation or
      # multi-platform descriptors) or one layer would be preserved by
      # reference while only the [0] blobs are copied, so it is rejected
      # — never silently discarded.
      manifest_count="$(jq '.manifests | length' "$index")"
      test "$manifest_count" = 1 || {
        echo "unsupported input: index.json must declare exactly one manifest, found $manifest_count" >&2
        exit 1
      }
      manifest_digest="$(jq -r '.manifests[0].digest' "$index")"
      require_sha256 "$manifest_digest"
      manifest_hex="''${manifest_digest#sha256:}"
      manifest_blob="$PWD/.work/docker/blobs/sha256/$manifest_hex"

      # Fail closed: every blob named by the index and the manifest must
      # exist and hash to exactly its digest.
      check_blob() {
        blob="$PWD/.work/docker/blobs/sha256/''${1#sha256:}"
        test -f "$blob" || { echo "missing blob $1" >&2; exit 1; }
        computed="$(sha256sum "$blob" | cut -d' ' -f1)"
        test "$computed" = "''${1#sha256:}" || {
          echo "blob digest mismatch: expected $1, got sha256:$computed" >&2
          exit 1
        }
      }
      test -f "$manifest_blob" || { echo "missing manifest blob" >&2; exit 1; }
      computed="$(sha256sum "$manifest_blob" | cut -d' ' -f1)"
      test "$computed" = "$manifest_hex" || { echo "manifest blob digest mismatch" >&2; exit 1; }
      config_digest="$(jq -r '.config.digest' "$manifest_blob")"
      layer_digest="$(jq -r '.layers[0].digest' "$manifest_blob")"
      require_sha256 "$config_digest"
      require_sha256 "$layer_digest"
      layer_count="$(jq '.layers | length' "$manifest_blob")"
      test "$layer_count" = 1 || {
        echo "unsupported input: image manifest must declare exactly one layer, found $layer_count" >&2
        exit 1
      }
      check_blob "$config_digest"
      check_blob "$layer_digest"
      config_blob="$PWD/.work/docker/blobs/sha256/''${config_digest#sha256:}"
      layer_blob="$PWD/.work/docker/blobs/sha256/''${layer_digest#sha256:}"
      test "$(jq -r '.config.size' "$manifest_blob")" = "$(stat -c %s "$config_blob")" || {
        echo "config size mismatch" >&2
        exit 1
      }
      test "$(jq -r '.layers[0].size' "$manifest_blob")" = "$(stat -c %s "$layer_blob")" || {
        echo "layer size mismatch" >&2
        exit 1
      }
      # Fail closed: validate every embedded tool INSIDE the layer —
      # image-root component resolution and the module/cacert/fonts
      # contract (see inImageValidation). Validation-only extraction:
      # the Nix store dirs inside the layer are mode 0555 and the
      # builder user is not root, so --delay-directory-restore keeps
      # them writable until extraction completes (plain
      # --no-same-permissions leaves them 0555 mid-stream and children
      # fail to mkdir); the repacked archive preserves the ORIGINAL
      # layer blob bytes, never this extraction.
      tar -xf "$layer_blob" -C "$PWD/.work/root" \
        --no-same-permissions --no-same-owner --delay-directory-restore
      image_root="$PWD/.work/root"
      ${inImageValidation}

      ${identitiesJson}
      image_config_json="$(jq '{
        user: (.config.User // null),
        working_dir: (.config.WorkingDir // null),
        entrypoint: (.config.Entrypoint // null),
        command: (.config.Cmd // null),
        env: (.config.Env // [])
      }' "$config_blob")"

      # Deterministic repack: preserve the index and the manifest, config,
      # and layer blob bytes exactly; the pin is the unchanged manifest
      # digest.
      install -m 0444 "$manifest_blob" "$PWD/.work/oci/blobs/sha256/$manifest_hex"
      install -m 0444 "$config_blob" \
        "$PWD/.work/oci/blobs/sha256/''${config_digest#sha256:}"
      install -m 0444 "$layer_blob" \
        "$PWD/.work/oci/blobs/sha256/''${layer_digest#sha256:}"
      install -m 0444 "$index" "$PWD/.work/oci/index.json"
      printf '{"imageLayoutVersion":"1.0.0"}\n' > "$PWD/.work/oci/oci-layout"
      tar -C "$PWD/.work/oci" ${tarFlags} -cf "$out/odin-workload-image-oci.tar" .
      archive_sha256="$(sha256sum "$out/odin-workload-image-oci.tar" | cut -d' ' -f1)"

      image_name="$(jq -r '.manifests[0].annotations["io.containerd.image.name"] // empty' "$index" | sed 's/:[^/]*$//')"
      tag="$(jq -r '.manifests[0].annotations["org.opencontainers.image.ref.name"] // empty' "$index")"
      import_archive="odin-workload-image-oci.tar"

      ${identityJson}
    ''
else
  let
    ompLauncher = "${ompStock}/bin/omp";
    odinExecutable = "${odinBin}/bin/odin";
    odindExecutable = "${odinBin}/bin/odind";
    nodeExecutable = "${pkgs.nodejs_22}/bin/node";
    playwrightModule = pkgs.playwright-driver;
    chromiumExecutable = "${pkgs.chromium}/bin/chromium";
    xvfbExecutable = "${pkgs.xvfb}/bin/Xvfb";
    tmuxExecutable = "${pkgs.tmux}/bin/tmux";
    # Official server, source and npm dependencies pinned by flake.lock's nixpkgs.
    filesystemExecutable = "${pkgs.mcp-server-filesystem}/bin/mcp-server-filesystem";
    claudeExecutable =
      if claudeCode == null then
        builtins.throw "workload-image: from-source mode requires claudeCode (the flake passes it)"
      else
        "${claudeCode}/bin/claude";

    # The pinned shared harness extension module: shipped verbatim under
    # /odin/lib/odin-extension so the image identity can name the exact
    # entry bytes the composed extension policy is bound to. From-source
    # mode cannot pack without it.
    extensionModule =
      if odinExtension == null then
        builtins.throw "workload-image: from-source mode requires the odinExtension derivation (flake packages.odin-extension)"
      else
        odinExtension;
    extensionEntry = "${extensionModule}/index.ts";

    # Display alias only; the manifest digest is the identity. The suffix
    # is the shared revisionAlias provenance (git rev or odin drv hash).
    tag = "${ompStock.version}-${lib.strings.substring 0 12 revisionAlias}";
    imageName = "localhost/odin-workload";

    # Stable in-image paths for every declared mechanism input. The links
    # double as derivation references, so the image closure carries the
    # playwright module, the pinned harness extension module, and the
    # fonts the odind binary's compiled defaults name.
    odinTools = pkgs.runCommand "odin-workload-tools" { } ''
      mkdir -p "$out/odin/bin" "$out/odin/etc" "$out/odin/lib"
      ln -s ${ompLauncher} "$out/odin/bin/omp"
      ln -s ${odinExecutable} "$out/odin/bin/odin"
      ln -s ${odindExecutable} "$out/odin/bin/odind"
      ln -s ${nodeExecutable} "$out/odin/bin/node"
      ln -s ${chromiumExecutable} "$out/odin/bin/chromium"
      ln -s ${xvfbExecutable} "$out/odin/bin/Xvfb"
      ln -s ${tmuxExecutable} "$out/odin/bin/tmux"
      ln -s ${claudeExecutable} "$out/odin/bin/claude"
      ln -s ${filesystemExecutable} "$out/odin/bin/mcp-server-filesystem"
      ln -s ${playwrightModule} "$out/odin/lib/playwright-core"
      ln -s ${extensionModule} "$out/odin/lib/odin-extension"
      ln -s ${fontConf} "$out/odin/etc/fonts.conf"
    '';

    fontConf = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };

    imageRoot = pkgs.buildEnv {
      name = "odin-workload-image-root";
      paths = [
        odinTools
        pkgs.bash
        pkgs.coreutils
        pkgs.cacert
        pkgs.python3
        pkgs.git
      ];
      pathsToLink = [
        "/odin"
        "/bin"
        "/etc"
      ];
      ignoreCollisions = true;
    };

    # The runtime supplies the command; no seat-specific entrypoint belongs in the image.
    imageConfig = {
      User = "65534:65534";
      WorkingDir = "/state";
      Env = [
        "PATH=/odin/bin:/bin"
        "HOME=/state"
        "TMPDIR=/tmp"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
        "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
        "FONTCONFIG_FILE=/odin/etc/fonts.conf"
      ];
    };

    image = pkgs.dockerTools.buildImage {
      name = imageName;
      inherit tag;
      copyToRoot = imageRoot;
      config = imageConfig;
      # World-writable scratch for Chromium and Xvfb; /state and /export
      # are the documented mount points the declared volumes shadow.
      extraCommands = ''
        mkdir -m 1777 tmp
        mkdir -m 0755 state export
        # The declared SSL_CERT_FILE/NIX_SSL_CERT_FILE contract names
        # /etc/ssl/certs/ca-certificates.crt, while pkgs.cacert ships
        # ca-bundle.crt in a 0555 directory — make the directory
        # writable, then expose the real bundle under the declared
        # conventional path so runtime TLS cannot silently lose its
        # trust store.
        chmod u+w etc/ssl/certs
        ln -s ca-bundle.crt etc/ssl/certs/ca-certificates.crt
      '';
    };

    # Fail closed: every embedded tool and the extension entry module
    # must be a real build input. A context-less store path would only
    # surface as an empty hash or a dangling in-image link, so verify
    # presence before hashing.
    toolGuard = ''
      for tool in ${ompLauncher} ${odinExecutable} ${odindExecutable} \
        ${nodeExecutable} ${chromiumExecutable} ${xvfbExecutable} \
        ${tmuxExecutable} ${claudeExecutable} ${filesystemExecutable} ${extensionEntry}; do
        test -f "$tool" || {
          echo "workload image: embedded tool missing from build inputs: $tool" >&2
          exit 1
        }
      done
    '';
  in
  pkgs.runCommand "odin-workload-image"
    {
      nativeBuildInputs = [
        pkgs.b3sum
        pkgs.coreutils
        pkgs.findutils
        pkgs.jq
      ];
    }
    ''
      mkdir -p "$out" "$PWD/.work/docker" "$PWD/.work/oci/blobs/sha256" "$PWD/.work/root"
      install -m 0444 "${image}" "$PWD/.work/docker-image.tar.gz"

      # Fail closed: see toolGuard.
      ${toolGuard}

      # Fail closed on a pinned odin build predating the carrier mechanism:
      # the admitted workload launch composes the carrier pod's PID1 from
      # exactly this odind entrypoint with the mechanism-only passive argv
      # (crates/odin-cli/src/odind/workload_park.rs PASSIVE_ARGV), so the
      # shipped binary must admit that argv, PARK for the whole window — an
      # immediate exit is the silent Succeeded-pod defect this mechanism
      # replaces — and exit cleanly under the pod-level stop. Nothing here
      # reads config, state, or the network; the KILL bound keeps a carrier
      # that ignores the stop from hanging the build.
      parked_at="$(date +%s)"
      timeout --signal=TERM --kill-after=5 --preserve-status 5 \
        "${odindExecutable}" workload-park > /dev/null 2>&1 || {
        echo "workload image: the pinned odind does not implement the passive carrier argv or does not exit cleanly on SIGTERM" >&2
        exit 1
      }
      test "$(( $(date +%s) - parked_at ))" -ge 4 || {
        echo "workload image: the passive carrier argv did not park until the stop signal" >&2
        exit 1
      }

      # Unpack the docker archive and derive the canonical manifest from
      # the ACTUAL blob digests, then emit the OCI layout with those exact
      # preserved bytes.
      tar -xzf "$PWD/.work/docker-image.tar.gz" -C "$PWD/.work/docker"
      config_name="$(jq -r '.[0].Config' "$PWD/.work/docker/manifest.json")"
      layer_path="$(jq -r '.[0].Layers[0]' "$PWD/.work/docker/manifest.json")"
      config_digest="sha256:$(sha256sum "$PWD/.work/docker/$config_name" | cut -d' ' -f1)"
      config_size="$(stat -c %s "$PWD/.work/docker/$config_name")"
      layer_digest="sha256:$(sha256sum "$PWD/.work/docker/$layer_path" | cut -d' ' -f1)"
      layer_size="$(stat -c %s "$PWD/.work/docker/$layer_path")"

      # Fail closed: prove the built image content in-place before any
      # repack — the same in-image resolution rules the normalize mode
      # enforces on external archives (see inImageValidation). The layer
      # media type must state the real compression: sniff the magic
      # bytes once, extract accordingly, and feed the same value to the
      # manifest below.
      image_root="$PWD/.work/root"
      case "$(dd if="$PWD/.work/docker/$layer_path" bs=2 count=1 2>/dev/null)" in
        $'\x1f\x8b')
          layer_gz="z"
          layer_media_type="application/vnd.docker.image.rootfs.diff.tar.gzip"
          ;;
        *)
          layer_gz=""
          layer_media_type="application/vnd.docker.image.rootfs.diff.tar"
          ;;
      esac
      tar -x''${layer_gz}f "$PWD/.work/docker/$layer_path" -C "$image_root" \
        --no-same-permissions --no-same-owner --delay-directory-restore
      ${inImageValidation}

      jq -cn \
        --arg config_digest "$config_digest" \
        --argjson config_size "$config_size" \
        --arg layer_digest "$layer_digest" \
        --argjson layer_size "$layer_size" \
        --arg layer_media_type "$layer_media_type" \
        '{
          schemaVersion: 2,
          mediaType: "application/vnd.docker.distribution.manifest.v2+json",
          config: {
            mediaType: "application/vnd.docker.container.image.v1+json",
            size: $config_size,
            digest: $config_digest
          },
          layers: [
            {
              mediaType: $layer_media_type,
              size: $layer_size,
              digest: $layer_digest
            }
          ]
        }' > "$PWD/.work/manifest.json"
      manifest_digest="sha256:$(sha256sum "$PWD/.work/manifest.json" | cut -d' ' -f1)"

      install -m 0444 "$PWD/.work/manifest.json" \
        "$PWD/.work/oci/blobs/sha256/''${manifest_digest#sha256:}"
      install -m 0444 "$PWD/.work/docker/$config_name" \
        "$PWD/.work/oci/blobs/sha256/''${config_digest#sha256:}"
      install -m 0444 "$PWD/.work/docker/$layer_path" \
        "$PWD/.work/oci/blobs/sha256/''${layer_digest#sha256:}"
      printf '{"imageLayoutVersion":"1.0.0"}\n' > "$PWD/.work/oci/oci-layout"
      jq -cn \
        --arg manifest_digest "$manifest_digest" \
        --argjson manifest_size "$(stat -c %s "$PWD/.work/manifest.json")" \
        --arg ref_name "${imageName}:${tag}" \
        --arg image_ref "${imageName}@$manifest_digest" \
        '{
          schemaVersion: 2,
          manifests: [
            {
              mediaType: "application/vnd.docker.distribution.manifest.v2+json",
              digest: $manifest_digest,
              size: $manifest_size,
              annotations: {
                # Canonical governed reference: containerd import
                # registers an image under EXACTLY this name, so the
                # digest-pinned k8s launch resolves without tag
                # substitution or post-import tagging.
                "io.containerd.image.name": $image_ref,
                "org.opencontainers.image.ref.name": $ref_name
              }
            }
          ]
        }' > "$PWD/.work/oci/index.json"
      tar -C "$PWD/.work/oci" ${tarFlags} -cf "$out/odin-workload-image-oci.tar" .
      archive_sha256="$(sha256sum "$out/odin-workload-image-oci.tar" | cut -d' ' -f1)"

      ${identitiesJson}
      image_config_json="$(jq -n \
        --arg user "${imageConfig.User}" \
        --arg working_dir "${imageConfig.WorkingDir}" \
        --argjson env '${builtins.toJSON imageConfig.Env}' \
        '{
          user: $user,
          working_dir: $working_dir,
          entrypoint: null,
          command: null,
          env: $env
        }')"
      import_archive="odin-workload-image-oci.tar"
      # The shared identity emitter reads these as shell variables; the
      # ref_name annotation above composes the same values.
      image_name="${imageName}"
      tag="${tag}"

      ${identityJson}
    ''
