# One ast-grep backend with a pinned TOML parser, never project-selected native libraries.
{ pkgs }:
let
  configuration = (pkgs.formats.yaml { }).generate "odin-ast-grep.yml" {
    ruleDirs = [ ];
    customLanguages.toml = {
      libraryPath = "${pkgs.tree-sitter-grammars.tree-sitter-toml}/parser";
      extensions = [ "toml" ];
      expandoChar = "_";
    };
  };
  # ast-grep 0.50 added an explicit opt-in for native parsers. The configuration
  # is always this immutable store file, including on older locked nixpkgs.
  parserPolicy = pkgs.lib.optionalString (pkgs.lib.versionAtLeast pkgs.ast-grep.version "0.50") "--custom-languages allow";
in
pkgs.writeShellApplication {
  name = "odin-ast-grep";
  text = ''
    case "''${1-}" in
      run) shift ;;
      --version|-V|--help|-h) exec ${pkgs.ast-grep}/bin/ast-grep "$@" ;;
      *) echo "odin-ast-grep expects run" >&2; exit 2 ;;
    esac
    exec ${pkgs.ast-grep}/bin/ast-grep run --config ${configuration} ${parserPolicy} "$@"
  '';
}
