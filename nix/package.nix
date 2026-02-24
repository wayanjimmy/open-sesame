{
  lib,
  rustPlatform,
  pkg-config,
  installShellFiles,
  fontconfig,
  wayland,
  wayland-protocols,
  libxkbcommon,
}:

let
  cargoToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  version = cargoToml.package.version;

  src = ./..;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "cosmic-client-toolkit-0.1.0" = "sha256-KvXQJ/EIRyrlmi80WKl2T9Bn+j7GCfQlcjgcEVUxPkc=";
      "cosmic-protocols-0.1.0" = "sha256-KvXQJ/EIRyrlmi80WKl2T9Bn+j7GCfQlcjgcEVUxPkc=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    installShellFiles
  ];

  buildInputs = [
    fontconfig
    wayland
    wayland-protocols
    libxkbcommon
  ];

  # Build only the main binary, not xtask
  cargoBuildFlags = [ "--package" "open-sesame" ];
  cargoTestFlags = [ "--package" "open-sesame" ];

  # Tests that create $HOME/.cache/ dirs fail in the nix sandbox (/homeless-shelter)
  # Standard nixpkgs pattern — used by atuin, spacetimedb, zabbix-cli, nushell, etc.
  preCheck = ''
    export HOME=$(mktemp -d)
  '';

  # Generate man pages and shell completions via xtask
  postBuild = ''
    cargo run --package xtask -- man
    cargo run --package xtask -- completions
  '';

  postInstall = ''
    installManPage target/man/sesame.1.gz

    installShellCompletion --cmd sesame \
      --bash target/completions/sesame.bash \
      --zsh target/completions/_sesame \
      --fish target/completions/sesame.fish

    install -Dm644 config.example.toml $out/share/doc/open-sesame/config.example.toml
  '';

  meta = with lib; {
    description = "Vimium-style window switcher for COSMIC desktop";
    homepage = "https://github.com/ScopeCreep-zip/open-sesame";
    license = licenses.gpl3Only;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "sesame";
  };
}
