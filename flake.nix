{
  description = "Odin control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    omp = {
      url = "github:can1357/oh-my-pi/e996e1c7ac476f60e02b8ed9764cf30fa8c00a8e";
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
            nativeBuildInputs = [
              pkgs.patchelf
              pkgs.makeWrapper
            ];
            # NixOS keeps libnvidia-ml.so.1 under /run/opengl-driver/lib.
            # The path is the driver location, not a host name.
            # `odin view` execs this bun on the view's entry; the wrapper
            # sets both so view and extension edits leave the Rust build alone.
            postFixup = ''
              for bin in "$out/bin/odin" "$out/bin/odind"; do
                patchelf --add-rpath /run/opengl-driver/lib "$bin"
              done
              wrapProgram "$out/bin/odin" \
                --set ODIN_VIEW_ENTRY ${odinView}/main.ts \
                --set ODIN_VIEW_BUN ${pkgs.bun}/bin/bun
            '';
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
          # The terminal view runs as plain TypeScript by bun. Its PNG decoder is
          # pinned separately so the installed view needs no network or npm install.
          odinView = pkgs.runCommand "odin-view" {
            pngjs = pkgs.fetchurl {
              url = "https://registry.npmjs.org/pngjs/-/pngjs-7.0.0.tgz";
              hash = "sha512-LKWqWJRhstyYo9pGvgor/ivk2w94eSjE3RGVuzLGlr3NmD8bf7RcYGze1mNdEHRP6TRP6rMuDHk5t44hnTRyow==";
            };
          } ''
            cp -r ${
              pkgs.lib.fileset.toSource {
                root = ./view;
                fileset = pkgs.lib.fileset.difference ./view (
                  pkgs.lib.fileset.unions [
                    ./view/dev
                    ./view/test
                  ]
                );
              }
            } "$out"
            chmod -R u+w "$out"
            mkdir -p "$TMPDIR/pngjs" "$out/node_modules"
            rm -rf "$out/node_modules/pngjs"
            tar --delay-directory-restore --no-same-permissions -xzf "$pngjs" -C "$TMPDIR/pngjs" --strip-components=1
            # npm's archive records both package directories as 0666, without search permission.
            chmod u+rwx "$TMPDIR/pngjs" "$TMPDIR/pngjs/lib"
            mv "$TMPDIR/pngjs" "$out/node_modules/pngjs"
          '';
          authorityWireV2Generated = pkgs.runCommand "odin-authority-wire-v2-generated" { } ''
            mkdir -p "$out/generated"
            install -m 0444 ${./extension/generated/odin-authority-wire-v2.ts} \
              "$out/generated/odin-authority-wire-v2.ts"
            install -m 0444 ${./extension/generated/odin-authority-wire-v2.conformance.mjs} \
              "$out/generated/odin-authority-wire-v2.conformance.mjs"
          '';
        in
        rec {
          default = odin;
          omp-stock = omp.packages.${system}.omp;
          odin-extension = odinExtension;
          odin-view = odinView;
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
          odin-look = import ./nix/look.nix { inherit pkgs; };
          odin-ast-grep = import ./nix/ast-grep.nix { inherit pkgs; };
          obscura = pkgs.callPackage ./nix/obscura.nix { inherit craneLib; };
          # web.read's fetch with Chrome's network fingerprint, after the plain reader is refused.
          fetch-impersonated = pkgs.writers.writePython3Bin "odin-fetch-impersonated" {
            libraries = [ pkgs.python3Packages.curl-cffi ];
            doCheck = false;
          } (builtins.readFile ./nix/fetch-impersonated.py);
          # web.read's PDF tables: pdfplumber's tables as Markdown, after the document's text.
          pdf-tables = pkgs.writers.writePython3Bin "odin-pdf-tables" {
            libraries = [ pkgs.python3Packages.pdfplumber ];
            doCheck = false;
          } (builtins.readFile ./nix/pdf-tables.py);
          # The workload image's declared CLI tools as one /bin, for the authority's own recon
          # sandbox (osint.recon from a seat): the same paths a pod sees.
          pod-tools = pkgs.symlinkJoin {
            name = "odin-pod-tools";
            paths = import ./nix/pod-tools.nix pkgs ++ [ pkgs.coreutils ];
          };
          odin-devices = pkgs.callPackage ./nix/devices.nix { inherit craneLib; };
          odind = odindCli;
          odin-sidecar = odinSidecar;
          odin-effector = odinEffector;
          odin-worker-bootstrap = odinWorkerBootstrap;
          # The one Claude Code: pods run it and the fleet's hosts install it.
          # Newer than the nixpkgs pin; same native-binary package, manifest overridden.
          claude-code =
            (import nixpkgs {
              inherit system;
              config.allowUnfreePredicate = pkg: nixpkgs.lib.getName pkg == "claude-code";
            }).claude-code.override
              {
                manifest = {
                  version = "2.1.311";
                  platforms."linux-x64" = {
                    binary = "claude.zst";
                    checksum = "d0c00b80761f3030f34cf0812266f6c6f8210ff9af7242f7c6c76c5600499caf";
                  };
                };
              };
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
            claudeCode = claude-code;
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
          # code.look end to end in the build sandbox (its loopback is the bubble's): serve a page, shoot it.
          odin-look-smoke =
            let
              site = pkgs.writeTextDir "index.html" "<!doctype html><title>Smoke</title><h1>Look</h1>";
            in
            pkgs.runCommand "odin-look-smoke" { nativeBuildInputs = [ pkgs.jq ]; } ''
              export HOME="$TMPDIR"
              mkdir -p "$out"
              ${self.packages.${system}.odin-look}/bin/odin-look --serve ${site} \
                --url http://127.0.0.1:4173/ --widths 390,1280 --out .odin-eval/look > result.json || { cat result.json; exit 1; }
              jq -e '([.shots[].width] == [390,1280]) and all(.shots[]; .title == "Smoke")' result.json
              cp .odin-eval/look/look-390.png .odin-eval/look/look-1280.png "$out/"
              cp result.json "$out/result.json"
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
                (pkgs.mergiraf.overrideAttrs (_: {
                  doCheck = false;
                }))
                pkgs.poppler-utils
                pkgs.openssh
                pkgs.typescript
                pkgs.gitleaks
                # Gate checks. ast-grep is for tools/design-check.py.
                pkgs.ast-grep
                pkgs.typos
                pkgs.ruff
                pkgs.shellcheck
                pkgs.biome
                pkgs.cargo-nextest
                pkgs.cargo-machete
                pkgs.tokei
                pkgs.sccache
                # odin-brain's Postgres tests start a throwaway cluster; `cargo sqlx prepare` refreshes .sqlx/.
                (pkgs.postgresql_17.withPackages (ps: [
                  ps.pgvector
                  ps.pg_search
                ]))
                pkgs.sqlx-cli
              ]
              ++ pkgs.lib.optionals (system == "x86_64-linux") [ pkgs.mold ];
            env = {
              ODIN_PINNED_OMP_VERSION = ompVersionFor system;
              ODIN_PINNED_OMP_SOURCE_REVISION = ompSourceRevision;
              ODIN_TEST_BWRAP = "${pkgs.bubblewrap}/bin/bwrap";
              # One content-keyed compiler cache (~/.cache/sccache) for every worktree and the gate;
              # 10G keeps pc's disk (94% full) well below the 30G it had grown to.
              RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
              SCCACHE_CACHE_SIZE = "10G";
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
