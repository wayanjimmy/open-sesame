{
  description = "Open Sesame - Vimium-style window switcher for COSMIC desktop";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/package.nix { };
        open-sesame = self.packages.${system}.default;
      });

      overlays.default = final: prev: {
        open-sesame = final.callPackage ./nix/package.nix { };
      };

      homeManagerModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.open-sesame;
          tomlFormat = pkgs.formats.toml { };
          defaultPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          options.programs.open-sesame = {
            enable = lib.mkEnableOption "Open Sesame window switcher for COSMIC desktop";

            package = lib.mkOption {
              type = lib.types.package;
              default = defaultPkg;
              description = "The open-sesame package to use.";
            };

            settings = lib.mkOption {
              type = tomlFormat.type;
              default = { };
              example = lib.literalExpression ''
                {
                  settings = {
                    activation_key = "alt+space";
                    overlay_delay = 720;
                    quick_switch_threshold = 250;
                    background_color = "#000000c8";
                    card_color = "#1e1e1ef0";
                    text_color = "#ffffffff";
                    hint_color = "#646464ff";
                  };
                  keys.g = {
                    apps = [ "ghostty" "com.mitchellh.ghostty" ];
                    launch = "ghostty";
                  };
                  keys.f = {
                    apps = [ "firefox" "org.mozilla.firefox" ];
                    launch = "firefox";
                  };
                }
              '';
              description = ''
                Configuration for Open Sesame, written to
                {file}`~/.config/open-sesame/config.toml`.

                See {command}`sesame --print-config` for default values
                and https://scopecreep-zip.github.io/open-sesame/ for documentation.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            xdg.configFile."open-sesame/config.toml" = lib.mkIf (cfg.settings != { }) {
              source = tomlFormat.generate "open-sesame-config" cfg.settings;
            };
          };
        };

      devShells = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];
            packages = with pkgs; [
              cargo
              rustc
              rust-analyzer
              clippy
              rustfmt
            ];
          };
        });
    };
}
