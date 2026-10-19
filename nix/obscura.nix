# Obscura's pinned rusty_v8 version requires matching release archives and generated bindings.
{
  craneLib,
  fetchFromGitHub,
  fetchurl,
  stdenv,
  rustPlatform,
  pkg-config,
  zstd,
}:
let
  v8Version = "150.4.0";
  target = stdenv.hostPlatform.rust.rustcTarget;
  v8Release = "https://github.com/denoland/rusty_v8/releases/download/v${v8Version}";
  common = {
    pname = "obscura";
    version = "0.1.0-unstable-2026-10-04";
    src = fetchFromGitHub {
      owner = "h4ckf0r0day";
      repo = "obscura";
      rev = "1fccab2c1ecd0f7eadc16d7a520ba227f9e7f782";
      hash = "sha256-thpUbGHwO2oU1kaIlrSp1RBonITVjyS8xocmlAZYpJ0=";
    };
    strictDeps = true;
    doCheck = false;
    cargoExtraArgs = "--locked -p obscura-cli";
    nativeBuildInputs = [
      rustPlatform.bindgenHook
      pkg-config
    ];
    buildInputs = [ zstd ];
    env = {
      RUSTY_V8_ARCHIVE = fetchurl {
        url = "${v8Release}/librusty_v8_simdutf_release_${target}.a.gz";
        hash = "sha256-9IdiyhDR8fxgWkQcWuQw7Izh6egPFNePvELLh4wwtHY=";
      };
      RUSTY_V8_SRC_BINDING_PATH = fetchurl {
        url = "${v8Release}/src_binding_simdutf_release_${target}.rs";
        hash = "sha256-dyeCauR5vbZF6Acjn7EtH44uI956bPFvXuWSaQ0dhQY=";
      };
      ZSTD_SYS_USE_PKG_CONFIG = "1";
    };
  };
in
craneLib.buildPackage (
  common
  // {
    cargoArtifacts = craneLib.buildDepsOnly common;
    meta.mainProgram = "obscura";
  }
)
