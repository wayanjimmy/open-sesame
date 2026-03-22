## Quick Install

### APT Repository (recommended)

```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
sudo apt update
```

**Desktop** (window switcher + clipboard + input + headless):
```bash
sudo apt install -y open-sesame open-sesame-desktop
```

**Headless** (secrets, profiles, launcher, snippets — no GUI):
```bash
sudo apt install -y open-sesame
```

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

## What You Get

### open-sesame (headless)
- **Encrypted secret vaults** with multi-factor auth (password + SSH agent)
- **Trust profiles** with context-driven activation
- **Application launcher** with fuzzy search and secret injection
- **Snippet expansion** with variable substitution

### open-sesame-desktop (requires open-sesame)
- **Alt+Space** — Window switcher overlay with Vimium-style letter hints
- **Alt+Tab** — Quick-switch to previous window
- **Clipboard manager** with security classification
- **Keyboard input capture** for compositor-independent shortcuts

## Documentation

- **[User Guide](https://scopecreep-zip.github.io/open-sesame/book/)** — Configuration, keybindings, theming
- **[API Docs](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/)** — Library reference

## Supply Chain Security

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

