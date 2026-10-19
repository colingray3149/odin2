{ self }:
{
  pkgs,
  lib,
  config,
  ...
}:
let
  odinPackages = self.packages.${pkgs.stdenv.hostPlatform.system};
  cfg = config.services.odin;
  # The daemon needs writable harness roots; ensureOdinHarnessCaches creates them before sandboxing.
  ompRuntimePaths = map (dir: "${config.home.homeDirectory}/.omp/${dir}") [
    "run"
    "cache"
    "logs"
  ];
  # Generated settings: the operator's settings with kube.image_identity
  # injected from the workloadImageIdentity option when [kube] is declared —
  # one declared source, never two manual redundant settings.
  # Workload gateway credentials are operator-declared in settings under
  # [kube.gateway_credentials]: each projection credential_handle maps to
  # { secret = "<k8s secret name>"; key = "<secret key>" }; kube injects the
  # value into the carrier pod env via SecretKeyRef and it never appears in
  # settings, argv, the image, or logs.
  # [gateway_host_credentials] maps each handle to a host environment variable name, never its value.
  effectiveSettings =
    let
      # The identity is injected only when declared; an enabled host with [kube] but no identity is refused by the
      # assertion below, while disabled follower declarations (e.g. mini) must still evaluate.
      withImage =
        if (cfg.settings.kube or null) == null || cfg.workloadImageIdentity == null then
          cfg.settings
        else
          lib.recursiveUpdate cfg.settings {
            kube.image_identity = "${cfg.workloadImageIdentity}";
          };
    in
    # Declared adapter backends render their [adapter_backends.<id>] argv.
    if cfg.adapterBackends == { } then
      withImage
    else
      withImage
      // {
        adapter_backends = lib.mapAttrs (_: backend: { inherit (backend) argv; }) cfg.adapterBackends;
      };
  odindToml = (pkgs.formats.toml { }).generate "odind.toml" effectiveSettings;
  odindFixtureToml =
    let
      executables =
        effectiveSettings.executables
          or (throw "services.odin ODIN-07 fixture base requires settings.executables.");
      browser =
        executables.browser
          or (throw "services.odin ODIN-07 fixture base requires settings.executables.browser.");
      missing = builtins.filter (name: !(browser ? ${name})) [
        "policy"
        "protected_values"
      ];
    in
    if missing != [ ] then
      throw "services.odin ODIN-07 fixture base requires settings.executables.browser.${builtins.head missing}."
    else
      (pkgs.formats.toml { }).generate "odind-fixture.toml" (
        effectiveSettings
        // {
          executables = executables // {
            browser = browser // {
              # The composition builder replaces these paths with fixtures from the same output.
              policy = "@odin-fixture-policy@";
              protected_values = "@odin-fixture-protected-values@";
            };
          };
        }
      );
  # The strict browser virtual-display setting is the one source of the
  # exact Xvfb identity: when configured, the composition records it as a
  # manifest executable (verbatim path, digest over the target bytes), so
  # the broker admits exactly that binding instead of an ambient program.
  xvfbBinary = ((cfg.settings.executables.browser or { }).display or { }).xvfb_binary or null;
  browserPolicyFile = "${cfg.stateRoot}/browser/browser-policy.json";
  browserProtectedValuesFile = "${cfg.stateRoot}/browser/protected-values.json";
  browserPolicyInstall = pkgs.writeShellScript "odin-install-browser-policy-inputs" ''
    set -euo pipefail
    ${pkgs.coreutils}/bin/install -d -m 0700 \
      ${lib.escapeShellArg "${cfg.stateRoot}/browser"} \
      ${lib.escapeShellArg "${cfg.stateRoot}/browser/profiles"}
    ${pkgs.coreutils}/bin/install -m 0444 ${toString cfg.browserPolicyInputs.policy} ${lib.escapeShellArg browserPolicyFile}
    ${pkgs.coreutils}/bin/install -m 0600 ${toString cfg.browserPolicyInputs.protectedValues} ${lib.escapeShellArg browserProtectedValuesFile}
  '';

  # Match registry implementation IDs to declared backend executables and argv.
  adapterExecutables = lib.mapAttrs' (
    id: backend: lib.nameValuePair "adapter.${id}" backend.executable
  ) cfg.adapterBackends;
  # Stock OMP has no models-file flag and no seat sandbox. This wrapper
  # confines the OMP process: it execs the bwrap options Rust wrote from
  # the seat declaration (ODIN_SEAT_SANDBOX). It does not assemble mounts
  # or network flags. The seat shell is the /bin/bash wrapper bound inside
  # that bubble. A launch without the profile is refused. `--version`
  # stays on the stock binary so identity probing needs neither the
  # profile nor model state.
  stockOmp = "${odinPackages.omp-stock}/bin/omp";
  ompExecutable = pkgs.writeShellScript "odin-omp-seat-sandbox" ''
    set -euo pipefail
    if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
      exec ${stockOmp} "$@"
    fi
    if [ -z "''${ODIN_SEAT_SANDBOX:-}" ]; then
      echo "Odin OMP launch has no seat sandbox profile (ODIN_SEAT_SANDBOX); refusing an unconfined process" >&2
      exit 1
    fi
    ${lib.optionalString (cfg.ompSettingsOverlay != null) ''
      set -- "$@" --config ${lib.escapeShellArg (toString cfg.ompSettingsOverlay)}
    ''}
    exec ${pkgs.bubblewrap}/bin/bwrap --args 3 3< "$ODIN_SEAT_SANDBOX" -- ${stockOmp} "$@"
  '';
  executablesMap = {
    odin = "${cfg.package}/bin/odin";
    odind = "${cfg.package}/bin/odind";
    sweep = "${odinPackages.sweep}/bin/sweep";
    odin-sidecar = "${odinPackages.odin-sidecar}/bin/odin-sidecar";
    odin-effector = "${odinPackages.odin-effector}/bin/odin-effector";
    # The web-search adapter binary the integration sweep's worker tests
    # drive (ODIN_TEST_ADAPTER_WEB_EXECUTABLE); declared adapters bind
    # their own `adapter.<id>` keys.
    odin-adapter-web = "${odinPackages.odin-adapter-web}/bin/odin-adapter-web";
    omp = ompExecutable;
    omp-stock = stockOmp;
    git = "${pkgs.git}/bin/git";
    zellij = "${pkgs.zellij}/bin/zellij";
    bun = "${pkgs.bun}/bin/bun";
    python3 = "${pkgs.python3}/bin/python3";
    browser_node = "${pkgs.nodejs_22}/bin/node";
    nix = "${pkgs.nix}/bin/nix";
    ss = "${pkgs.iproute2}/bin/ss";
    gitleaks = "${pkgs.gitleaks}/bin/gitleaks";
    cargo = "${pkgs.cargo}/bin/cargo";
    rustc = "${pkgs.rustc}/bin/rustc";
    rustdoc = "${pkgs.rustc}/bin/rustdoc";
    cc = "${pkgs.stdenv.cc}/bin/cc";
    pkg-config = "${pkgs.pkg-config}/bin/pkg-config";
    bash = "${pkgs.bash}/bin/bash";
    cp = "${pkgs.coreutils}/bin/cp";
    mkdir = "${pkgs.coreutils}/bin/mkdir";
    chmod = "${pkgs.coreutils}/bin/chmod";
    jq = "${pkgs.jq}/bin/jq";
    b3sum = "${pkgs.b3sum}/bin/b3sum";
    stat = "${pkgs.coreutils}/bin/stat";
    tailscale = "${pkgs.tailscale}/bin/tailscale";
    mount = "${pkgs.util-linux}/bin/mount";
    ssh = "${pkgs.openssh}/bin/ssh";
    ssh-keygen = "${pkgs.openssh}/bin/ssh-keygen";
    worker_bootstrap = "${cfg.workerBootstrap}/bin/odin-worker-bootstrap";
    unshare = "${pkgs.util-linux}/bin/unshare";
    env = "${pkgs.coreutils}/bin/env";
    timeout = "${pkgs.coreutils}/bin/timeout";
    systemd-run = "${pkgs.systemd}/bin/systemd-run";
    systemctl = "${pkgs.systemd}/bin/systemctl";
    loginctl = "${pkgs.systemd}/bin/loginctl";
    xdpyinfo = "${pkgs.xdpyinfo}/bin/xdpyinfo";
    xprop = "${pkgs.xprop}/bin/xprop";
    scanner = cfg.scanner;
    ohshit = "${cfg.operatorStopPackage}/bin/ohshit";
    bwrap = "${pkgs.bubblewrap}/bin/bwrap";
  }
  // (lib.optionalAttrs (xvfbBinary != null) {
    xvfb = xvfbBinary;
  })
  // adapterExecutables;
  composition = pkgs.callPackage ../composition.nix {
    configFile = odindToml;
    fixtureConfigFile = odindFixtureToml;
    fixturePolicy = ../../sweep/fixtures/home/odin-07/browser-policy.json;
    fixtureProtectedValues = ../../sweep/fixtures/home/odin-07/protected-values.json;
    executables = executablesMap;
  };
  # The installed sweep runs from the user profile, outside the odind unit,
  # so it carries its runtime inputs as wrapper defaults: every --set-default
  # fills only a variable the caller left unset, and an explicit environment
  # value always wins. The manifest-bound sweep executable stays the raw
  # package because the broker context inherits the unit environment already.
  # Single pinned-source root: the activated flake revision's read-only
  # store copy (self.outPath). Both installed wrappers and the daemon's
  # registry derivation read from it, so registry definitions, schemas, and
  # compiled metadata always come from the revision the pinned binaries
  # were built from — never from a moving authoring checkout.
  pinnedSourceRoot = toString cfg.sourceRoot;
  # Dormant followers receive source defaults without demanding authority inputs.
  sweepWrapped = pkgs.symlinkJoin {
    name = "odin-sweep";
    paths = [ odinPackages.sweep ];
    nativeBuildInputs = [ pkgs.makeWrapper ];
    meta = odinPackages.sweep.meta or { };
    postBuild = ''
      wrapProgram "$out/bin/sweep" \
        --set-default ODIN_ROOT ${lib.escapeShellArg pinnedSourceRoot} \
        ${lib.optionalString cfg.enable "--set-default ODIN_RUNTIME_MANIFEST ${lib.escapeShellArg (toString cfg.runtimeManifest)}"} \
        ${lib.optionalString (
          cfg.enable && cfg.litellmConfig != null
        ) "--set-default SWEEP_LITELLM_CONFIG ${lib.escapeShellArg (toString cfg.litellmConfig)}"}
    '';
  };
  # The profile-installed odin CLI carries the host's strict composition
  # config as a wrapper DEFAULT environment (ODIN_CONFIG): an
  # `odin session --interactive --provider <declared> --model <declared>`
  # resolves the declared odind.toml with no hand-copied path (the launch
  # pair stays an explicit selection: no default is inferred). ODIN_ROOT
  # defaults to the same pinned source root, so
  # registry-reading commands (providers, seat menus, atlas) validate the
  # revision the pinned CLI parser was built from — a moving authoring
  # checkout can never feed unknown keys to an older deployed parser. An
  # explicit ODIN_ROOT in the environment still wins for development.
  # Only the profile entry is wrapped — services.odin
  # .package, the runtime manifest executable map, and the daemon unit keep
  # the raw package so every bound executable identity stays where it is.
  # The CLI reads ODIN_CONFIG exactly when a command's --config flag is
  # absent (explicit flag > environment > typed error naming both).
  odinCliWrapped = pkgs.symlinkJoin {
    name = "odin";
    paths = [ odinPackages.odin ];
    nativeBuildInputs = [ pkgs.makeWrapper ];
    meta = odinPackages.odin.meta or { };
    postBuild = ''
      wrapProgram "$out/bin/odin" \
        --set-default ODIN_CONFIG ${lib.escapeShellArg (toString cfg.configFile)} \
        --set-default ODIN_ROOT ${lib.escapeShellArg pinnedSourceRoot}
    '';
  };
in
{
  options.services.odin = {
    enable = lib.mkEnableOption "the private Odin controller user service";
    package = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      default = odinPackages.odin;
      description = "Odin controller package providing odin and odind.";
    };
    ompLauncher = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = ompExecutable;
      description = "Immutable OMP launcher path independent of manifestExecutables; safe for settings inputs.";
    };
    workloadImageIdentity = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Immutable workload image identity.json (odin.workload-image-identity.v1) from the pinned workload-image build; safe for settings inputs. The single operator-declared source: when settings declare a [kube] section this path is injected as kube.image_identity automatically, so settings never restate it.";
    };
    configFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${composition}/odind.toml";
      description = "Strict Nix-generated odind.toml copied into and digest-bound by the runtime composition.";
    };
    runtimeManifest = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${composition}/runtime-manifest.json";
      description = "Digest-bound runtime support manifest.";
    };
    fixtureBase = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${composition}/fixtures/odin-07";
      description = "ODIN-07 conformance fixture base inside the composition output.";
    };
    compositionPackage = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      default = composition;
      description = "Exact composed Odin runtime closure.";
    };
    candidateLauncher = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${composition}/bin/odind-candidate";
      description = "Unswitched daemon launcher bound to this composition's config and runtime manifest.";
    };
    candidateDescriptor = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${composition}/candidate.json";
      description = "Immutable candidate launcher/config/manifest binding descriptor.";
    };
    manifestExecutables = lib.mkOption {
      type = lib.types.attrsOf lib.types.path;
      readOnly = true;
      default = executablesMap;
      description = "Exact manifest executable paths; consumers must reuse these expressions verbatim.";
    };
    extensionPath = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = "${odinPackages.odin-extension}/index.ts";
      description = "Odin extension entry module file pinned by odind and session workers.";
    };
    browserPolicyFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = browserPolicyFile;
      description = "Runtime browser policy location inside the private state root.";
    };
    browserProtectedValuesFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = browserProtectedValuesFile;
      description = "Runtime protected-values location (materialized mode 0600) inside the private state root.";
    };

    adapterBackends = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            executable = lib.mkOption {
              type = lib.types.str;
              description = "Absolute /nix/store path of the adapter backend binary (runtime manifest key adapter.<id>).";
            };
            argv = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Static argv the backend is launched with for every framed call.";
            };
          };
        }
      );
      default = { };
      description = "Declared out-of-process adapter backends keyed by adapter id (FINAL-PASS W4.4). Registry capabilities with implementation = <id> route to the backend.";
    };
    browserPolicyInstaller = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = browserPolicyInstall;
      description = "Exact runtime policy materializer used by the user unit and unswitched candidate launcher.";
    };
    browserPolicyInputs = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.submodule {
          options = {
            policy = lib.mkOption {
              type = lib.types.path;
              description = "Composed browser policy snapshot bytes.";
            };
            protectedValues = lib.mkOption {
              type = lib.types.path;
              description = "Composed protected-value marker bytes; installed owner-only.";
            };
          };
        }
      );
      default = null;
      description = "Browser policy inputs installed into the private state before odind starts; required exactly when settings declare executables.browser.";
    };
    ompModelsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional immutable OMP models.yml overlay consumed by the manifest-bound stock launcher without relocating HOME or credentials.";
    };
    writablePaths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      description = "Additional absolute paths the controller and its payloads may write (for example the approved project roots); the state root is always writable.";
    };
    trustedHarnessWritablePaths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      description = "Narrow host-only state paths needed by the trusted OMP harness (for example its SQLite auth store); never propagated into model tool or eval sandboxes.";
    };
    operatorStopPackage = lib.mkOption {
      type = lib.types.package;
      description = "Required operator emergency-stop package; no fallback.";
    };
    ompSettingsOverlay = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional immutable settings overlay appended via the stock-supported --config flag (highest precedence over global and project settings); never a mutation of the user's own configuration.";
    };
    sourceRoot = lib.mkOption {
      type = lib.types.path;
      # The activated flake revision's own read-only store copy: the module
      # ships inside that input, so self.outPath is always exactly the tree
      # the pinned binaries were built from. An explicit override (a real
      # authoring checkout for development) remains possible, but then
      # settings.paths.registry_root must follow it (asserted below).
      default = self.outPath;
      description = "Odin source repository root whose registry and schemas the installed sweep and odin CLI wrappers read as their ODIN_ROOT default and whose registry/ the daemon's settings.paths.registry_root must name; defaults to the activated revision's store copy.";
    };
    litellmConfig = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Immutable LiteLLM gateway config handed to the installed sweep as SWEEP_LITELLM_CONFIG.";
    };
    workerBootstrap = lib.mkOption {
      type = lib.types.package;
      default = odinPackages.odin-worker-bootstrap;
      description = "Pinned worker bootstrap package.";
    };
    scanner = lib.mkOption {
      type = lib.types.path;
      description = "Pinned browser malware scanner executable.";
    };
    stateRoot = lib.mkOption {
      type = lib.types.path;
      default = "${config.home.homeDirectory}/.local/state/odin";
      description = "Controller writable state root.";
    };
    registrySnapshot = lib.mkOption {
      type = lib.types.path;
      description = "Active published registry snapshot consumed by odind.";
    };
    settings = lib.mkOption {
      type = (pkgs.formats.toml { }).type;
      description = "Exact odin.odind-config.v1 structure, emitted without constructor defaults.";
    };
  };

  config = lib.mkMerge [
    {
      home.packages = [
        sweepWrapped
        (if cfg.enable then odinCliWrapped else odinPackages.odin)
      ];
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = (cfg.settings.schema or "") == "odin.odind-config.v1";
          message = "services.odin.settings.schema must be odin.odind-config.v1.";
        }
        {
          assertion = (cfg.settings.kube or null) == null || cfg.workloadImageIdentity != null;
          message = "services.odin.workloadImageIdentity must be set when settings declare a [kube] section: workload admission refuses without the pinned image identity.";
        }
        {
          assertion = (cfg.settings.paths.state_root or "") == toString cfg.stateRoot;
          message = "services.odin.stateRoot must equal settings.paths.state_root.";
        }
        {
          assertion = (cfg.settings.paths.registry_snapshot or "") == toString cfg.registrySnapshot;
          message = "services.odin.registrySnapshot must equal settings.paths.registry_snapshot.";
        }
        {
          assertion =
            (cfg.browserPolicyInputs != null) == ((cfg.settings.executables.browser or null) != null);
          message = "services.odin.browserPolicyInputs is required exactly when settings declare executables.browser.";
        }
        {
          assertion =
            cfg.browserPolicyInputs == null
            || (
              (cfg.settings.executables.browser.policy or "") == toString cfg.browserPolicyFile
              &&
                (cfg.settings.executables.browser.protected_values or "") == toString cfg.browserProtectedValuesFile
            );
          message = "settings.executables.browser policy inputs must equal the services.odin state policy paths.";
        }
        {
          # Registry, atlas, schemas, and binaries must use the same pinned revision.
          assertion = (cfg.settings.paths.registry_root or "") == "${toString cfg.sourceRoot}/registry";
          message = "services.odin settings.paths.registry_root must equal \"\${toString config.services.odin.sourceRoot}/registry\" so registry definitions and schemas stay pinned to the activated revision.";
        }
      ];
      services.odin.settings.paths.registry_root = lib.mkDefault "${toString cfg.sourceRoot}/registry";
      # A disabled unit must be absent: a leaf mkIf emits an empty unit that systemd treats as masked.
      systemd.user.services = lib.mkMerge [
        (lib.mkIf cfg.enable {
          odind = {
            Unit = {
              Description = "Odin private controller";
              After = [ "graphical-session.target" ];
              PartOf = [ "graphical-session.target" ];
            };
            Service = {
              Type = "simple";
              ExecStartPre = [
                (lib.mkIf (cfg.browserPolicyInputs != null) "${browserPolicyInstall}")
              ];
              ExecStart = "${cfg.package}/bin/odind huginn --config ${cfg.configFile}";
              Environment = [
                "ODIN_RUNTIME_MANIFEST=${cfg.runtimeManifest}"
                "ODIN_BWRAP=${pkgs.bubblewrap}/bin/bwrap"
                "ODIN_BASH=${pkgs.bash}/bin/bash"
                "ODIN_PYTHON3=${pkgs.python3}/bin/python3"
                "ODIN_PATH_EXTRA=${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin"
              ]
              ++ lib.optional (cfg.ompModelsFile != null) "ODIN_OMP_MODELS=${cfg.ompModelsFile}"
              ++ [
                "ODIN_PROVIDER_AUTH=${config.home.homeDirectory}/.config/sops-nix/secrets/rendered/litellm-env"
              ];
              Restart = "on-failure";
              RestartSec = 5;
              RuntimeDirectory = "odin";
              PrivateTmp = true;
              ProtectSystem = "strict";
              ReadWritePaths = [
                cfg.stateRoot
              ]
              ++ cfg.writablePaths
              ++ cfg.trustedHarnessWritablePaths
              ++ ompRuntimePaths;
              NoNewPrivileges = true;
            };
            Install.WantedBy = [ "default.target" ];
          };
        })
      ];

    })
  ];
}
