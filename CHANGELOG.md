# Changelog

All notable changes to this project will be documented in this file.

## [3.0.0] - 2026-05-27

Major release focused on detection depth — extra coverage layer for
deeper SS analysis. **34 scanners** total (was 25).

### Added

#### 🧬 Live process analysis (`live_analysis.py`)
- `scan_roblox_dll_injection` — lists ALL DLLs loaded into running
  `RobloxPlayerBeta.exe` / `Windows10Universal.exe` processes, flags
  unsigned DLLs (via `WinVerifyTrust`), DLLs in suspicious paths
  (`%TEMP%`, `%APPDATA%`, `Downloads`, `Desktop`), and DLLs whose name
  matches an executor keyword. **Catches injected cheats even if the
  on-disk file was deleted.**
- `scan_process_tree` — verifies that Roblox was spawned by a legit
  parent (`explorer.exe`, `bloxstrap.exe`, `RobloxPlayerLauncher.exe`,
  major browsers). Suspicious parent = possible injector chain.

#### 📜 Command history (`command_history.py`)
- `scan_powershell_history` — reads `ConsoleHost_history.txt`, the
  append-only log of every PowerShell command ever typed. Flags
  `iex (irm krnl.cat/...)`-style one-liner installers, AMSI bypasses,
  Defender exclusion mods, `bitsadmin` / `wget` / `curl` downloads,
  base64-encoded commands, event-log clears, USN journal deletes.
- `scan_runmru` — Win+R history from HKCU Registry.
- `scan_typed_paths` — paths typed into the Explorer address bar.

#### 🖱️ Peripheral macros (`peripherals.py`)
- `scan_mouse_software_installed` — detects G HUB, Logitech Gaming
  Software, Razer Synapse, Bloody (A4Tech), X-Mouse Button Control,
  SteelSeries GG, Corsair iCUE, HyperX NGENUITY, Redragon.
- `scan_logitech_ghub_scripts` — opens G HUB's SQLite `settings.db`,
  reads stored macro Lua scripts, flags keywords: `no recoil`,
  `recoil control`, `auto headshot`, `rapid fire`, `aim assist`,
  `MoveMouseRelative`, etc.
- `scan_xmouse_profiles` and `scan_razer_synapse` — same logic
  against their profile/config files.

#### 🖥️ Multi-monitor screenshot (`capture.py`)
- `capture_all_monitors` enumerates monitors via `EnumDisplayMonitors`
  and captures each one separately. Default `capture_all()` now
  captures **every monitor** + Roblox window. Cheater hiding HUD on
  monitor 2 is now exposed.

### Changed
- Banner: `v3.0 · 34 scanners · DLL live scan · PS history · Multi-monitor · Macros`.
- Added CLI flags: `--no-live`, `--no-history`, `--no-peripherals`.
- Build script: added new hidden imports for the new modules.
- Database additions: `POWERSHELL_RED_FLAGS` (50+ patterns),
  `MACRO_RED_FLAGS` (30+ patterns), `MOUSE_SOFTWARE` registry,
  `ROBLOX_PROCESS_NAMES`, `TRUSTED_DLL_PATHS`, `SUSPICIOUS_DLL_PATHS`.

### Fixed
- Process tree no longer false-flags when parent process can't be
  read due to permission (waits for admin).

## [2.0.0] - 2026-05-27

### Added
- Massive database expansion: **542 detection signatures** (from ~194).
  - `EXECUTOR_KEYWORDS`: 65 → 164 entries
  - `EXECUTOR_PROCESS_NAMES`: 26 → 89 entries
  - `SUSPICIOUS_DOMAINS`: 33 → 104 entries
  - `SUSPICIOUS_FOLDER_NAMES`: 18 → 80 entries
  - `SCRIPT_RED_FLAGS`: 39 → 105 entries
- New executors covered: Xeno, Cryptic, Empyrean, Valyse, Bunni Hub, Cosmic,
  Acrylix, Marin, Coral, Furk Os, Sense, Karambit X, Drumix, Omega X,
  Apex Hardware, Stellar Spoof, Sploitware, CCDownloader, Cellura, Hexus,
  Verbose, Ninja Hub, Valex, Pylon, Fenix, Ronin, Swift X.
- New categories: HWID spoofers (rage/perm/tbhd), kernel mappers
  (kdmapper, drvmap, ezmapper, intelmapper, manualmapper), anti-cheat
  bypass tools (byfron/hyperion killers), debugger/reverser detection
  (IDA, Ghidra, dnSpy, x32/64dbg, OllyDbg, windbg), gray-hat marketplaces
  (elitepvpers, unknowncheats, guidedhacking, mpgh).
- Popular hubs detection: Owl, Dark, Infinite Yield, Hoho, Epix, Vape v4,
  Vape Lite, Fates Admin, Kraken, Rip, Rocky, Fluxus Hub, Thresh.
- Per-game hubs: Blox Fruits, Pet Sim, Arsenal, Phantom Forces, Doors,
  Criminality, Da Hood.
- ~40 new script red flags: `newcclosure`, `checkcaller`, `iscclosure`,
  `getnamecallmethod`, `setnamecallmethod`, `firetouchinterest`,
  `fireclickdetector`, `fireproximityprompt`, `decompile`, `getscripts`,
  `getloadedmodules`, `getinstances`, `getnilinstances`, `getgc`, `getreg`,
  `saveinstance`, `_G.aimbot`, `_G.esp`, `killall`, `btools`, `byfron`,
  `hyperion`, `antitamper`, etc.

### Removed
- **BREAKING:** Discord webhook integration removed. `webhook.py` deleted,
  `--webhook` flag removed, `DISCORD_WEBHOOK_URL` env var no longer read.
  Tool is now 100% local — no network egress anywhere.

### Changed
- Banner updated to `v3.1 · 25 scanners · 542 signatures · Paralelo · 100% local`.
- Build no longer bundles `mimetypes` / `urllib` hidden imports (webhook only).

## [1.0.0] - 2026-05-26

### Added
- Public repository bootstrap with documentation and policy files.
- Initial `.gitignore` for Python and build artifacts.
- Initial `README.md`, `LICENSE`, and `SECURITY.md`.
- GitHub Actions workflow for syntax and import smoke checks.

### Notes
- This release focuses on project publishing readiness and CI baseline.
