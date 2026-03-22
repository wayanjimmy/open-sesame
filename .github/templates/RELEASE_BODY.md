
---

## Download Checksums

### open-sesame (headless)

| File | SHA256 |
|------|--------|
| `open-sesame-linux-x86_64.deb` | `${SHA256_HEADLESS_X86_64}` |
| `open-sesame-linux-aarch64.deb` | `${SHA256_HEADLESS_AARCH64}` |

### open-sesame-desktop

| File | SHA256 |
|------|--------|
| `open-sesame-desktop-linux-x86_64.deb` | `${SHA256_DESKTOP_X86_64}` |
| `open-sesame-desktop-linux-aarch64.deb` | `${SHA256_DESKTOP_AARCH64}` |

### Quick Install (auto-detects architecture)

**Desktop (full suite):**
```bash
ARCH=$(uname -m)
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-${ARCH}.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-${ARCH}.deb" -o /tmp/open-sesame-desktop.deb
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```

**Headless only:**
```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-$(uname -m).deb" -o /tmp/open-sesame.deb
sudo dpkg -i /tmp/open-sesame.deb
```

### x86_64 (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-x86_64.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-x86_64.deb" -o /tmp/open-sesame-desktop.deb
echo "${SHA256_HEADLESS_X86_64}  /tmp/open-sesame.deb" | sha256sum -c -
echo "${SHA256_DESKTOP_X86_64}  /tmp/open-sesame-desktop.deb" | sha256sum -c -
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```

### aarch64 (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-aarch64.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-aarch64.deb" -o /tmp/open-sesame-desktop.deb
echo "${SHA256_HEADLESS_AARCH64}  /tmp/open-sesame.deb" | sha256sum -c -
echo "${SHA256_DESKTOP_AARCH64}  /tmp/open-sesame-desktop.deb" | sha256sum -c -
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```
