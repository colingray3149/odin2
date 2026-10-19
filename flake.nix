{
  description = "Odin control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    omp = {
      url = "github:can1357/oh-my-pi/2a2c6dcbbb558c0f8145f67f28b3370984f2bf60";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      omp,
      crane,
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      # Single source of truth: the pinned omp flake input feeds both the
      # stock package version (ODIN_PINNED_OMP_VERSION) and its source
      # revision (ODIN_PINNED_OMP_SOURCE_REVISION, = omp.sourceInfo.rev) to
      # every consumer (package bakes, cargo checks, devShells, the odind
      # startup revision check, and the workload image identity). Never a
      # second literal for either.
      ompVersionFor = system: omp.packages.${system}.omp.version;
      ompSourceRevision = omp.sourceInfo.rev;
      sweepRuntimeInputsFor =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        with pkgs;
        [
          bash
          bubblewrap
          bun
          cargo
          cargo-deny
          clippy
          coreutils
          findutils
          git
          gnugrep
          iproute2
          nix
          nodejs_22
          openssl
          pkg-config
          rustc
          rustfmt
          stdenv.cc
          systemd
          util-linux
        ];
    in
    {
      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          sweepRuntimeInputs = sweepRuntimeInputsFor system;
          craneLib = crane.mkLib pkgs;
          # What the binaries compile from. registry/ and skeletons/ are read
          # only by tests, so a runtime declaration never rebuilds Odin.
          odinSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
              ./schemas
              ./extension
            ];
          };
          packageExecutableIdentities = cargoPackage: ''
            metadata="$out/share/odin/${cargoPackage}/package-build.json"
            ${pkgs.jq}/bin/jq '.executables = {}' "$metadata" > "$metadata.next"
            mv "$metadata.next" "$metadata"
            for binary in "$out"/bin/*; do
              if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then continue; fi
              name=$(${pkgs.coreutils}/bin/basename "$binary")
              canonical=$(${pkgs.coreutils}/bin/readlink -f "$binary")
              case "$canonical" in "$out/"*) ;; *) echo "foreign executable in first-party package" >&2; exit 1;; esac
              digest="blake3:$(${pkgs.b3sum}/bin/b3sum --no-names "$canonical")"
              ${pkgs.jq}/bin/jq --arg id "$name" --arg path "$canonical" --arg blake3 "$digest" \
                '.executables[$id] = {path: $path, blake3: $blake3}' "$metadata" > "$metadata.next"
              mv "$metadata.next" "$metadata"
              wrapped="$out/bin/.$name-wrapped"
              if [ -f "$wrapped" ] && [ -x "$wrapped" ]; then
                payload=$(${pkgs.coreutils}/bin/readlink -f "$wrapped")
                case "$payload" in "$out/"*) ;; *) echo "foreign payload in first-party package" >&2; exit 1;; esac
                payload_digest="blake3:$(${pkgs.b3sum}/bin/b3sum --no-names "$payload")"
                ${pkgs.jq}/bin/jq --arg id "$name" --arg path "$payload" --arg blake3 "$payload_digest" \
                  '.executables[$id].payload = {path: $path, blake3: $blake3}' "$metadata" > "$metadata.next"
                mv "$metadata.next" "$metadata"
              fi
            done
          '';
          # The third-party graph builds once per Cargo.lock (crane); each Odin
          # commit compiles only the workspace crates on top of it. Binaries
          # embed their dependency list (cargo-auditable).
          odinBuildArgs = {
            pname = "odin-workspace";
            version = "0.0.0";
            src = odinSrc;
            strictDeps = true;
            doCheck = false;
            cargoExtraArgs = "--locked --workspace --bins";
          };
          odinDeps = craneLib.buildDepsOnly (
            odinBuildArgs
            // {
              buildPhaseCargoCommand = "cargoWithProfile build $cargoExtraArgs";
            }
          );
          odinWorkspace = craneLib.buildPackage (
            odinBuildArgs
            // {
              cargoArtifacts = odinDeps;
              nativeBuildInputs = [ pkgs.cargo-auditable ];
              cargoBuildCommand = "cargo auditable build --release";
              env = {
                SQLX_OFFLINE = "true";
                ODIN_BROWSER_NODE_BIN = "${pkgs.nodejs_22}/bin/node";
                ODIN_BROWSER_PLAYWRIGHT_MODULE = "${pkgs.playwright-driver}";
                ODIN_EXTENSION_PATH = "${odinExtension}/index.ts";
                # Compile-time pinned-OMP bindings: odin-omp reads both with
                # option_env! so the expected version AND the expected source
                # revision derive from the nix-pinned omp input instead of a
                # second literal. The revision is the same omp.sourceInfo.rev
                # the workload image binds as its identity.
                ODIN_PINNED_OMP_VERSION = ompVersionFor system;
                ODIN_PINNED_OMP_SOURCE_REVISION = ompSourceRevision;
              };
            }
          );
          mkRustPackage =
            {
              pname,
              cargoPackage,
              mainProgram ? pname,
              nativeBuildInputs ? [ ],
              postInstall ? "",
              postFixup ? "",
            }:
            pkgs.stdenvNoCC.mkDerivation {
              inherit pname nativeBuildInputs;
              meta.mainProgram = mainProgram;
              version = "0.0.0";
              dontUnpack = true;
              installPhase = ''
                runHook preInstall
                mkdir -p "$out/bin"
                ${pkgs.lib.concatMapStringsSep "\n"
                  (name: ''
                    install -m 0555 ${odinWorkspace}/bin/${name} "$out/bin/${name}"
                  '')
                  (
                    if cargoPackage == "odin-cli" then
                      [
                        "odin"
                        "odind"
                      ]
                    else
                      [ mainProgram ]
                  )
                }
                runHook postInstall
              '';
              postInstall = ''
                mkdir -p "$out/share/odin/${cargoPackage}"
                printf '{"schema":"odin.package-build-identity.v1","repository":"odin","revision":"%s","cargo_package":"%s"}\n' \
                  "${self.rev or self.dirtyRev or ""}" "${cargoPackage}" \
                  > "$out/share/odin/${cargoPackage}/package-build.json"
              ''
              + postInstall;
              postFixup = postFixup + packageExecutableIdentities cargoPackage;
            };
          odinCli = mkRustPackage {
            pname = "odin";
            cargoPackage = "odin-cli";
          };
          odindCli = odinCli.overrideAttrs (_: {
            meta.mainProgram = "odind";
          });
          odinAdapterWeb = mkRustPackage {
            pname = "odin-adapter-web";
            cargoPackage = "odin-adapter-web";
          };
          odinAdapterMcp = mkRustPackage {
            pname = "odin-adapter-mcp";
            cargoPackage = "odin-adapter-mcp";
          };
          odinSidecar = mkRustPackage {
            pname = "odin-sidecar";
            cargoPackage = "odin-sidecar";
          };
          odinWorkerBootstrap = mkRustPackage {
            pname = "odin-worker-bootstrap";
            cargoPackage = "odin-process";
          };
          odinEffector = mkRustPackage {
            pname = "odin-effector";
            cargoPackage = "odin-effector";
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postFixup = ''
              wrapProgram "$out/bin/odin-effector" \
                --set ODIN_WORKER_BOOTSTRAP_BIN \
                  ${odinWorkerBootstrap}/bin/odin-worker-bootstrap \
                --set ODIN_WORKER_UNSHARE_BIN ${pkgs.util-linux}/bin/unshare
            '';
          };
          odinExtension = pkgs.runCommand "odin-extension" { } ''
            mkdir -p "$out" "$out/generated"
            install -m 0444 ${./extension/odin.ts} "$out/index.ts"
            install -m 0444 ${./extension/generated/odin-authority-wire-v2.ts} \
              "$out/generated/odin-authority-wire-v2.ts"
          '';
          authorityWireV2Generated = pkgs.runCommand "odin-authority-wire-v2-generated" { } ''
            mkdir -p "$out/generated"
            install -m 0444 ${./extension/generated/odin-authority-wire-v2.ts} \
              "$out/generated/odin-authority-wire-v2.ts"
            install -m 0444 ${./extension/generated/odin-authority-wire-v2.conformance.mjs} \
              "$out/generated/odin-authority-wire-v2.conformance.mjs"
          '';
          # mainProgram is the Cargo binary name from crates/odin-launch;
          # the package attribute is the crate name.
          odinLaunch = mkRustPackage {
            pname = "odin-launch";
            cargoPackage = "odin-launch";
            mainProgram = "odin-acp";
          };
        in
        rec {
          default = odin;
          omp-stock = omp.packages.${system}.omp;
          odin-extension = odinExtension;
          odin-authority-wire-v2-generated = authorityWireV2Generated;

          sweep = mkRustPackage {
            pname = "odin-sweep";
            cargoPackage = "odin-sweep";
            mainProgram = "sweep";
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postFixup = ''
              wrapProgram "$out/bin/sweep" \
                --prefix PATH : ${pkgs.lib.makeBinPath sweepRuntimeInputs}
            '';
          };

          odin = odinCli;
          odin-adapter-web = odinAdapterWeb;
          odin-adapter-mcp = odinAdapterMcp;
          obscura = pkgs.callPackage ./nix/obscura.nix { inherit craneLib; };
          odind = odindCli;
          odin-sidecar = odinSidecar;
          odin-effector = odinEffector;
          odin-worker-bootstrap = odinWorkerBootstrap;
          odin-launch = odinLaunch;
          # Confined workload-environment OCI image (M6b): the pinned OMP
          # launcher, the odin/odind browser-arm binaries, the pinned
          # shared harness extension module, and the browser display
          # mechanism with their real runtime dependencies. Identity
          # and contract: nix/workload-image.nix.
          workload-image = pkgs.callPackage ./nix/workload-image.nix {
            ompStock = omp-stock;
            ompRevision = omp.sourceInfo.rev;
            odinBin = odin;
            odinExtension = odin-extension;
            # Keep the native package at the protocol-qualified version, matching
            # the human host manifest pin; older nixpkgs defaults fail admission.
            claudeCode = (
              (import nixpkgs {
                inherit system;
                config.allowUnfreePredicate = pkg: nixpkgs.lib.getName pkg == "claude-code";
              }).claude-code.override
                {
                  manifest = {
                    version = "2.1.280";
                    platforms."linux-x64".checksum = "1e08503dbdf3c2cb0d706d32f3408277388d1c76ef108673e8fe42c1b322925b";
                  };
                }
            );
            sourceRevision = self.rev or self.dirtyRev or "";
          };
          # The image's identity.json alone: the ONE source every [kube]
          # surface reads, identical to the archive fleet nodes import,
          # without pulling the archive into a host's closure.
          workload-image-identity = pkgs.runCommand "odin-workload-image-identity.json" { } ''
            cp ${workload-image}/identity.json "$out"
          '';
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          rustComponents = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
          ];
          odinVendor = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
          };
          odinSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
              ./extension
              ./registry
              ./sweep/fixtures
              ./skeletons
              ./schemas
            ];
          };
          cargoCheck =
            name: command:
            pkgs.runCommand name
              {
                nativeBuildInputs = rustComponents ++ [
                  pkgs.pkg-config
                  pkgs.stdenv.cc
                ];
                buildInputs = [ pkgs.openssl ];
                src = odinSrc;
                ODIN_PINNED_OMP_VERSION = ompVersionFor system;
                ODIN_PINNED_OMP_SOURCE_REVISION = ompSourceRevision;
                SQLX_OFFLINE = "true";
              }
              ''
                export CARGO_HOME="$PWD/cargo-home"
                export CARGO_TARGET_DIR="$PWD/cargo-target"
                mkdir -p .cargo
                cat > .cargo/config.toml <<EOF
                [source.crates-io]
                replace-with = "vendored"

                [source.vendored]
                directory = "${odinVendor}"
                EOF
                cp -r "$src" ./src
                chmod -R u+w ./src
                cd ./src
                ${command}
                mkdir -p "$out"
                touch "$out/passed"
              '';
        in
        {
          workspace-cargo-build = cargoCheck "odin-workspace-cargo-build" ''
            cargo build --workspace --release --locked --offline
          '';
          odin-sweep-contract-tests = cargoCheck "odin-sweep-contract-tests" ''
            export PATH="${
              pkgs.lib.makeBinPath [
                pkgs.coreutils
                pkgs.git
                pkgs.nix
              ]
            }:$PATH"
            export HOME="$TMPDIR"
            cargo test -p odin-sweep --locked --offline
          '';
          declared-conversation-prompt =
            pkgs.runCommand "odin-declared-conversation-prompt"
              {
                nativeBuildInputs = [ pkgs.python3 ];
              }
              ''
                mkdir -p "$out"
                python3 ${odinSrc}/sweep/fixtures/conversation-prompt.py \
                  --omp ${self.packages.${system}.omp-stock}/bin/omp \
                  --seat ${odinSrc}/registry/seats/sinmara/seat.toml \
                  --output "$out/proof.json"
              '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          sweepRuntimeInputs = sweepRuntimeInputsFor system;
          fuzzPkgs = import nixpkgs {
            inherit system;
            overlays = [ omp.inputs.rust-overlay.overlays.default ];
          };
          # The overlay revision is locked transitively with OMP; "latest"
          # is therefore a fixed nightly manifest, not a moving download.
          fuzzToolchain = fuzzPkgs.rust-bin.nightly.latest.minimal.override { extensions = [ "rust-src" ]; };
        in
        {
          default = pkgs.mkShell {
            name = "odin";
            packages =
              sweepRuntimeInputs
              ++ [
                pkgs.python3
                pkgs.b3sum
                pkgs.gnutar
                pkgs.gzip
                pkgs.gnused
                pkgs.gawk
                pkgs.jq
                pkgs.procps
                pkgs.mergiraf
                pkgs.poppler-utils
                pkgs.openssh
                pkgs.typescript
                pkgs.gitleaks
                pkgs.cargo-nextest
                pkgs.cargo-machete
                pkgs.sccache
                # odin-brain's Postgres tests start a throwaway cluster; `cargo sqlx prepare` refreshes .sqlx/.
                (pkgs.postgresql_17.withPackages (ps: [ ps.pgvector ]))
                pkgs.sqlx-cli
              ]
              ++ pkgs.lib.optionals (system == "x86_64-linux") [ pkgs.mold ];
            env = {
              ODIN_PINNED_OMP_VERSION = ompVersionFor system;
              ODIN_PINNED_OMP_SOURCE_REVISION = ompSourceRevision;
              # One content-keyed compiler cache (~/.cache/sccache) for every worktree and the gate.
              RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
              SCCACHE_CACHE_SIZE = "30G";
              # sqlx checks queries against the committed .sqlx/ cache, never a live database.
              SQLX_OFFLINE = "true";
            }
            // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
              # Replaces .cargo/config.toml's rustflags in this shell only: mold links dev and test builds;
              # Nix package builds never see .cargo/ or this shell.
              CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C target-cpu=x86-64-v3 -C link-arg=-fuse-ld=mold";
            };
          };
          fuzz = pkgs.mkShell {
            name = "odin-fuzz";
            packages = [
              fuzzToolchain
              pkgs.cargo-fuzz
              pkgs.pkg-config
              pkgs.stdenv.cc
            ];
            env = {
              ODIN_PINNED_OMP_VERSION = ompVersionFor system;
              ODIN_PINNED_OMP_SOURCE_REVISION = ompSourceRevision;
              CARGO_BUILD_JOBS = "3";
            };
          };
        }
      );

      homeManagerModules.odin = import ./nix/modules/home.nix { inherit self; };
      homeManagerModules.default = self.homeManagerModules.odin;
    };
}
