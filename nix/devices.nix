# Installed device clients, built from this workspace rather than clone artifacts.
{
  craneLib,
  lib,
}:
let
  # Match on the path nix copies into the store. A prefix of the worktree
  # path never matches there, because cleanSourceWith rewrites the root.
  src = lib.cleanSourceWith {
    src = lib.cleanSource ./..;
    filter = path: type:
      let
        name = baseNameOf path;
        parent = baseNameOf (dirOf path);
        grand = baseNameOf (dirOf (dirOf path));
        device =
          parent == "bagd" || grand == "bagd"
        ;
      in
      (type == "directory" && lib.elem name [
        "crates" "bagd" "src" "tests"
      ])
      || (parent == "crates" && lib.hasSuffix ".toml" name)
      || device
      || (name == "Cargo.toml" || name == "Cargo.lock");
  };
  common = {
    pname = "odin-devices";
    version = "0.0.0";
    inherit src;
    strictDeps = true;
    cargoExtraArgs = lib.escapeShellArgs [
      "-p" "bagd"
    ];
    doCheck = false;
  };
in
craneLib.buildPackage (
  common
  // {
    cargoArtifacts = craneLib.buildDepsOnly common;
    meta.mainProgram = "flipper";
  }
)
