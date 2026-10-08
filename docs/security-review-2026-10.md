# LightCraft security & privacy evaluation (October 2026)

| | |
|---|---|
| **Scope** | Whole repository at commit `4159ceb` (workspace version 0.2.1): desktop app, CLI, MCP server, web (WASM) build, the 630-package dependency graph, CI/release pipeline, packaging scripts |
| **Date** | 2026-10-08 |
| **Method** | Manual code review; `cargo audit` 0.22.2 against the RustSec database (1,294 advisories, fetched on the review date); a scan of every third-party build script and crate payload; crates.io metadata for lesser-known crates; a proof of concept for the XMP slowdown; a live test of the control channel against the desktop app under Xvfb; `strace` traces of the built binaries (Linux) to see what network calls they really make |
| **Not covered** | Fuzzing of the image/raw decoders, runtime testing on Windows and macOS, signed release artifacts, the hosted web deployment |

## 1. Summary

LightCraft is in good shape for a 0.2 release. Every production crate forbids `unsafe` (the one exception is a single
FFI call in `crates/sysmem`). Clippy rules ban `unwrap`/`expect`/`panic`, and every decoder runs under `catch_unwind`.
Input-derived sizes are checked. The app has **no telemetry, analytics, crash reporting, update check or account**.
The only code that opens an outbound connection is an **opt-in** AI-model downloader. Traced under `strace`, the CLI,
the headless UI and the MCP server made **no network system calls at all**. The desktop app's only internet-family
socket was its loopback control listener (§4.3).

Most of the real risk sits in four places:

1. **The control channel (`--control PORT`) has no authentication.** When enabled, any local process or any other user
   on the machine can launch an arbitrary program, write files anywhere the user can, import or move photos, read the
   catalogue, and export any photo with its GPS to a folder of its choice. **All of this was confirmed against the
   running app.** Off by default, but the MCP/AI-agent workflow tells users to turn it on.
2. **Windows command injection** in "Edit in External Editor" when no editor is configured (`cmd /C start "" <path>`).
3. **Known-vulnerable `quick-xml` 0.38.4.** RUSTSEC-2026-0194 is reachable through the XMP sidecar merge that runs on
   **Cmd+S**. Reproduced: a 1.3 MB hostile `.xmp` costs about 20 s of CPU on the UI thread, and the cost grows
   quadratically.
4. **Supply chain of the release pipeline.** Signing secrets sit in jobs that use mutable third-party action tags.
   The AppImage runtime comes from an unpinned "continuous" download, and the Azure signing client from an unpinned
   NuGet package.

The dependency graph itself looks clean. All 606 third-party crates come from crates.io with lockfile checksums.
There are no git or `[patch]` sources, the 90 build scripts do nothing beyond the usual compiler probing, and no
typosquat or abandoned-namespace crates turned up. One choice stands out: the HTTPS client uses
`rustls-rustcrypto 0.0.2-alpha`, whose README says *"USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION"*.

### Findings at a glance

| ID | Finding | Severity | Component |
|---|---|---|---|
| S1 | Unauthenticated control channel: program launch, arbitrary file write, catalogue exfiltration | **High** (when enabled) | `apps/lightcraft/src/control_server.rs`, `crates/ui-egui/src/control.rs`, `menus.rs` |
| S2 | Windows command injection through `cmd /C start` in "Edit in External Editor" | **Medium** | `apps/lightcraft/src/main.rs` (`open_with`) |
| S3 | `quick-xml` 0.38.4 (RUSTSEC-2026-0194, reproduced) | **Medium** | `crates/meta/src/xmp_merge.rs` |
| S4 | Release pipeline: mutable action tags next to signing secrets; unpinned, unverified tool downloads; no dependency auditing in CI | **Medium** (high impact, low likelihood) | `.github/workflows/release.yml`, `packaging/` |
| S5 | TLS through an alpha, unmaintained crypto provider; HTTPS→HTTP redirects followed; tokenizer files not hash-pinned | **Medium** | `crates/fetch` |
| S6 | Zip bomb in preset import; 1-gigapixel default decode cap; unbounded sidecar reads | **Low** | `crates/engine/src/preset_import.rs`, `crates/codecs` |
| S7 | Dev web server: Windows drive-letter path traversal; no `Host` check | **Low** (developer-only) | `xtask/src/web.rs` |
| S8 | Hugging Face token passed on the `curl` command line | **Low** | `tools/install-sam3.sh` |
| S9 | MCP: no tool annotations; untrusted metadata flows into the LLM context; agents can set `acknowledged: true` | **Low** | `crates/mcp` |
| S10 | Unmaintained crates (`paste`, `ttf-parser`); advisories that can't be reached (`rsa`, `rustls-webpki` 0.102); startup panic when `libxkbcommon-x11` is missing | **Info** | `Cargo.lock`, `packaging/linux/nfpm.yaml` |
| S11 | No `SECURITY.md` or disclosure process; web build ships no Content-Security-Policy | **Info** | repository, `packaging/web/_headers` |

| ID | Privacy concern | Rating |
|---|---|---|
| P1 | Exports embed GPS, captions, keywords and camera data by default ("Remove Location" off); Original/DNG exports ignore the option | **Medium** |
| P2 | MCP/AI integration hands photo pixels and metadata (titles, captions, keywords, file names) to whichever LLM the client uses | **Medium** (usage-dependent) |
| P3 | "Show on Map" sends exact coordinates to openstreetmap.org | **Low** (user-initiated, labelled) |
| P4 | Model download shows the mirror your IP address, app version and use of SAM 3 | **Low** (opt-in) |
| P5 | Catalogue, previews and settings are unencrypted and created with the default umask | **Low** |

---

## 2. Security findings

### S1: Unauthenticated control channel (High when enabled)

`lightcraft --control PORT`, or the environment variable `LIGHTCRAFT_CONTROL_PORT`, starts a JSON-lines server on
`127.0.0.1:PORT` (`apps/lightcraft/src/control_server.rs`). It has a good defence against browsers: an HTTP request
line is rejected and the connection closed before any body runs, so a web page's cross-origin `fetch` or a DNS
rebinding attack can't drive it. It also caps line length and the number of open connections. But **any process that
can open a loopback socket is fully trusted**. `docs/control-protocol.md` admits as much ("The port has no
authentication").

Everything an MCP agent can do over this channel, any local client can do too. Through `engine.execute`, which
`app.run` dispatches to UI-only commands as well (`crates/ui-egui/src/lib.rs:266`):

- **Launch any program.** `photo.editInExternal` takes an `app` parameter, so the editor comes from the request, not
  from settings (`crates/ui-egui/src/menus.rs:888`), and the app runs `Command::new(app).arg(path).spawn()`
  (`apps/lightcraft/src/main.rs:254`; on macOS, `open -a <app>`).
- **Write files anywhere.** `ui.render` and `ui.screenshot` write PNGs to any path. `check_write_target` only protects
  catalogued originals and their sidecars (`crates/engine/src/originals.rs:89`), so files like `~/.bashrc` or
  `~/.ssh/authorized_keys` can be overwritten.
- **Read the catalogue and exfiltrate photos with their location.** `catalog.query` returns file names, titles,
  keywords and capture times straight over the socket. `app.export {dir}` writes any photo, with full metadata
  including GPS (the default policy, P1), into a folder the client chooses, and `ui.render` writes renders anywhere.
- **Move or rewrite originals.** `library.import` with `mode: "move"` to an attacker-chosen destination, plus
  batch renames, metadata edits and catalogue deletions.

**Who can reach it.**
- Any process running as the same user. That adds little on a single-user desktop, but it matters for code that is
  supposed to be contained: browser extensions with native messaging, sandboxed or containerised apps that share the
  host network namespace (e.g. Flatpak apps with `--share=network`), dev containers and WSL2 in mirrored mode.
- **Every other user on the machine.** Loopback is not per-user on Linux, macOS or Windows (terminal servers,
  shared lab machines, CI runners).

The MCP docs steer users to this mode (`lightcraft-cli mcp --connect`), so it is a real configuration, not just a
developer one.

**Verified live.** The desktop app ran under Xvfb (`lightcraft --memory --control 18731`). A separate Python
client, which sent no credentials, issued one JSON line per step:

| Request | Result |
|---|---|
| `engine.execute library.import {paths:[…/IMG_0001.png]}` | imported (`"imported": [25]`) |
| `engine.execute catalog.query {limit:1}` | file name, dimensions, keywords and title of the catalogue's photos |
| `engine.execute photo.setMeta {gps:"48.858370, 2.294481", caption:"home address"}` | `"changed": 1` |
| `engine.execute app.export {dir:"<attacker folder>", format:"jpeg"}` | JPEG written there; it contains the EXIF GPS IFD, `exif:GPSLatitude` in XMP, and the caption |
| `ui.render {path:"<any path>"}` | PNG written to that path |
| `engine.execute photo.editInExternal {app:"<path>/marker.sh"}` | **`marker.sh` executed by LightCraft**, with the rendered `IMG_0001-Edit.tif` as its argument (a harmless marker script stood in for a real payload) |

**Recommendations.**
1. Generate a random token at startup and write it to a file only the user can read (`0600`, in the settings
   folder). Require it as the first request (`{"method":"auth","params":{"token":…}}`); `lightcraft-cli mcp
   --connect` reads the same file. On Unix, a `0600` Unix-domain socket is even simpler.
2. Ignore `params.app` for `photo.editInExternal` when the request comes over the channel; use only the editor the
   user configured in Settings.
3. Limit `ui.render`/`ui.screenshot` paths to a scratch or export folder, or require the token from (1) before
   accepting any path.

### S2: Windows command injection in "Edit in External Editor" (Medium)

When no external editor is set, Windows opens the edit copy with
`Command::new("cmd").args(["/C", "start", ""]).arg(path)` (`apps/lightcraft/src/main.rs:247`). Rust's argument
quoting only adds quotes when an argument contains a space or tab. The `BatBadBut` fix (Rust 1.77.2) covers `.bat`
and `.cmd` programs, not an explicit `cmd.exe /C`. So `cmd.exe` re-parses the path, and its metacharacters (`&`, `^`,
`%VAR%`) take effect.

The path is the edit copy, `<folder of original>\<original stem>-Edit.tif` (`crates/engine/src/cmd/convert.rs`).
`ExportOptions::file_name_for` replaces only `/ \ : NUL`. If a photo's file name contains `&` followed by a command
and the full path has no spaces, "Edit in External Editor" (Ctrl+Shift+E on Windows) runs that command. A downloaded photo set
is a realistic way to deliver such a file.

**Recommendation.** Don't go through `cmd.exe`. Use `explorer.exe <path>`, or `ShellExecuteW` through a maintained
crate such as `opener`/`open`. If `cmd` must stay, escape the path with `^`, quote it, and reject `%` and `"`.
Add a regression test with a file name containing `&`.

### S3: `quick-xml` 0.38.4, RUSTSEC-2026-0194 reachable (Medium)

`cargo audit` reports two High (7.5) advisories against `quick-xml 0.38.4`, both fixed in ≥ 0.41.0. That version is
already in the lockfile through `wayland-scanner`. Reachability:

| Advisory | Code path | Reachable? |
|---|---|---|
| RUSTSEC-2026-0194: quadratic duplicate-attribute check | `crates/meta/src/xmp.rs` and `gpx.rs` call `attributes().with_checks(false)` | No |
| | `crates/meta/src/xmp_merge.rs:117` (`scan`) calls `e.attributes()` with checks on | **Yes** |
| RUSTSEC-2026-0195: `NsReader` namespace allocation | `NsReader` isn't used | No |

`merge_xmp` runs when LightCraft writes into an **existing** sidecar: "Save Metadata to File" (**Cmd+S**), or every
edit when "Automatically Write Changes into XMP" is on. It runs synchronously inside `Session::execute`, so the UI
freezes. `sidecar_contents` also reads the sidecar with no size cap (`crates/engine/src/sidecar.rs:351`). The element
cap (200,000 elements) doesn't help: a single element with many attributes is enough.

**Reproduction.** A standalone binary linked against `lightcraft-meta` at this commit (release build, one core)
calls `merge_xmp` on a sidecar with one `rdf:Description` carrying N attributes:

| Attributes | Sidecar size | `merge_xmp` | `parse_xmp` (checks off) |
|---:|---:|---:|---:|
| 16,000 | 149 KB | 0.35 s | 0.012 s |
| 32,000 | 309 KB | 1.26 s | 0.024 s |
| 64,000 | 629 KB | 5.85 s | 0.066 s |
| 128,000 | 1.3 MB | **20.5 s** | 0.117 s |

Doubling the input quadruples the time. A few-MB sidecar stalls the app for minutes, and the sidecar arrives next to
the photos it describes, so whoever supplies a photo set can supply one.

**Recommendation.** Upgrade the workspace to `quick-xml = "0.41"`. Until then, use `.with_checks(false)` in
`xmp_merge::scan` (`parse_xmp`, which runs first, already validates the packet). Cap the size of sidecar reads, e.g.
16 MB (Adobe's own XMP packets are KBs). Count attributes against the element budget.

### S4: Release-pipeline supply chain (Medium; high impact, low likelihood)

`release.yml` runs in the `release` environment, which holds the Apple certificate, the Windows PFX and the Azure
Trusted Signing client secret. Good points: workflow-level `permissions: contents: read`, `craft-fonts` pinned by
commit SHA, and `windows-arm64.yml` pins its actions by SHA. The release workflow, though, still has:

- **Mutable third-party action tags in jobs that hold secrets.** `dtolnay/rust-toolchain@stable`,
  `Swatinem/rust-cache@v2`, `actions/checkout@v4` and `actions/upload-artifact@v4` /
  `actions/download-artifact@v4`. A moved tag runs code in the same job that later reads the signing secrets
  (compare the tj-actions/changed-files compromise, CVE-2025-30066).
- **An unpinned, unverified `appimagetool`.** `packaging/linux/package.sh:107` downloads
  `releases/download/continuous/appimagetool-$ARCH.AppImage`, a rolling build with no checksum, runs it, and embeds
  its runtime in the shipped AppImage.
- **An unpinned, unverified Azure signing client.** `packaging/windows/sign.ps1:77` fetches
  `Microsoft.Trusted.Signing.Client` from NuGet with no version or hash and loads its DLL into `signtool` while
  `AZURE_CLIENT_SECRET` is in the environment.
- **A `nfpm` `.deb` installed with `sudo dpkg -i`** without a checksum (version pinned only).
- **No dependency auditing in CI.** No `cargo audit`/`cargo deny`, no Dependabot/Renovate configuration. The
  `quick-xml` advisory in S3 is three months old and nothing flagged it.
- **No provenance or SBOM.** Releases ship only `SHA256SUMS.txt`, produced by the same job that uploads them, with
  no signature or attestation, and the Linux packages are unsigned.

**Recommendations.** Pin every action by full commit SHA (as `windows-arm64.yml` already does). Pin `appimagetool`
to a tagged release and verify its SHA-256. Pin the NuGet package to a version and verify its hash. Verify `nfpm`'s
checksum. Add `cargo audit` (or `cargo deny check advisories bans sources`) to `cargo xtask ci` and a scheduled
workflow. Add `actions/attest-build-provenance` and an SBOM (`cargo cyclonedx`) to releases.

### S5: TLS stack and downloader integrity (Medium)

`crates/fetch` is a hand-written HTTP/1.1 client over `rustls 0.23.45` with the **`rustls-rustcrypto 0.0.2-alpha`**
crypto provider, chosen so the build stays pure Rust. That crate:

- tells users "USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION" and calls itself incomplete;
- hasn't been released since 2024-04-24 (218 k downloads in total, against tens of millions for `ring`/`aws-lc-rs`);
- pulls in `rustls-webpki 0.102.8` (four advisories) and `rsa 0.9.10` (Marvin attack).

Those advisories are **not reachable** here. The provider uses `webpki` 0.102 only for `alg_id` constants;
certificate path validation runs in rustls' own verifier on `rustls-webpki 0.103.15`, which is patched. No CRLs are
configured, and Marvin needs RSA private-key operations, which a TLS client verifying server signatures never does.
They are still a maintenance smell. The real risk is an undiscovered flaw in an unaudited provider.

The damage is limited because `model.safetensors` is pinned to an exact size and SHA-256, and `DEFAULT_MIRRORS` is
empty, so nothing is downloaded unless the user configures a mirror. Weaker spots:

- `vocab.json` and `merges.txt` aren't hash-pinned (`crates/segment/src/fetch/mod.rs:20`, flagged as a TODO).
- `Url::join` follows **HTTPS→HTTP redirects** (`crates/fetch/src/http.rs`), and `http://` mirrors are accepted.
  Combined with the unpinned files, a network attacker can replace the tokenizer files. The token itself is safe:
  it is sent only over TLS to the original host.
- Revocation isn't checked (no OCSP/CRL), which is normal for rustls clients.

**Recommendations.** Pin `vocab.json` and `merges.txt`. Refuse HTTPS→HTTP redirects and `http://` mirrors unless
the user explicitly allows them. Track `rustls-rustcrypto` and move to a maintained provider when the pure-Rust rule
allows (e.g. `graviola`/`rustls-graviola`, which has no C code but does use inline assembly; otherwise accept
`aws-lc-rs`/`ring` for the downloader alone).
Document the trade-off in `docs/ai-masks.md`.

### S6: Resource-exhaustion inputs (Low)

These can crash the app. Rust aborts on allocation failure, and `catch_unwind` can't catch an abort, so a crash loses
unsaved state:

- **Zip bomb in preset import.** `preset_import::read_zip` trusts each central-directory entry's declared size (up to
  4 GiB, with a limit of `2 × size + 1 KiB`). Entries may overlap and point at the same compressed data, and every
  inflated entry is kept in memory at once. A few-MB `.zip`/`.mplumpack` "preset pack" can therefore ask for tens of
  GB. Import is user-initiated, and preset packs are commonly shared online. **Fix:** cap the total inflated bytes
  (e.g. 64 MB for presets), refuse overlapping local-header offsets, and cap the entry count.
- **Image decode cap.** `DecodeOptions::default().max_pixels = 1 << 30` (about 1.07 gigapixels). At the pipeline's
  float precision that is up to ~16 GB of buffers, and a highly compressed PNG/JPEG of that size is small. **Fix:**
  lower the default to what the app supports (e.g. 512 MP, Lightroom's documented limit) and check free memory
  before the large allocations.
- **Unbounded reads.** Sidecar reads (`sidecar.rs:320,351`) and other `std::fs::read` calls on user files have no
  size cap.

### S7: Dev web server (Low, developer-only)

`cargo xtask web --serve` (`xtask/src/web.rs`) checks for `..` but not for absolute paths. On Windows,
`GET /C:/Users/<name>/secret.txt` gives `rel = "C:/Users/..."`, and `dir.join(rel)` replaces the base, so the file is
served. The server also doesn't check the `Host` header, which leaves a DNS-rebinding route to it from a malicious
page while it runs. **Fix:** reject components containing `:` and absolute paths, canonicalise and check the result
stays under `dir`, and only accept `Host: 127.0.0.1:<port>` / `localhost:<port>`.

### S8: Token on the command line (Low)

`tools/install-sam3.sh` passes `-H "Authorization: Bearer $TOKEN"` as a `curl` argument, so other local users can
read it in `ps` while the download runs. **Fix:** `curl -H @<(printf 'Authorization: Bearer %s' "$TOKEN")`, or
write a `0600` header file and pass `-H @file`. `install-sam3.ps1` is fine: it passes the token in-process through
`Invoke-WebRequest -Headers`.

### S9: MCP integration (Low)

- Every engine command, and in `--connect` mode every UI command too, becomes an MCP tool (`cmd_*`) with an open
  schema and **no `annotations`** (`readOnlyHint` / `destructiveHint`). The headless server listed 252 tools, none
  annotated. MCP clients therefore can't tell `query_photos` from `import {mode: "move"}` or
  `photo.editInExternal`, and can't apply confirmation policies.
- Tool results include **untrusted text from photo files** (titles, captions, keywords, file names), a path for
  prompt injection into the agent. Combined with S1's `app` parameter, injected text could talk an agent into
  launching a program.
- `segment.model.download` relies on the agent honestly setting `acknowledged: true` after asking the user.

**Recommendations.** Add MCP annotations from the command registry (a `destructive`/`readOnly` flag per command).
Leave UI-only and process-launching commands out of the MCP surface by default. Wrap metadata strings in tool
results so they are clearly data.

### S10: Dependency hygiene (Info)

- `paste 1.0.15` (RUSTSEC-2024-0436, a compile-time proc macro, via `gemm`/candle) and `ttf-parser 0.25.1`
  (RUSTSEC-2026-0192, parses only bundled fonts) are unmaintained. Low risk; they'll go away with upstream updates.
- `ring 0.17.14` and `glifo` appear in `Cargo.lock` but aren't in the resolved build graph for any target
  (`cargo tree -i ring --target all -e all`), so they are never compiled.
- `candle-*` is pinned to `=0.9.2` on purpose (newer releases pull in the C Oniguruma library). That pin will hold
  back security fixes in candle's dependency tree, so review it regularly.
- **A crash at startup when `libxkbcommon-x11` is missing.** On X11, winit's `xkbcommon-dl` panics ("Library
  libxkbcommon-x11.so could not be loaded"), which is how the first launch for this review failed. The `.deb`
  depends on `libxkbcommon0` but not `libxkbcommon-x11-0`, and the `.rpm` likewise lacks `libxkbcommon-x11`
  (`packaging/linux/nfpm.yaml`). Adding them keeps minimal installs from crashing on launch.

### S11: Process & web hardening (Info)

- No `SECURITY.md` or private reporting channel. Enable GitHub private vulnerability reporting and document it.
- `packaging/web/_headers` sets `nosniff` and cache headers but no `Content-Security-Policy` or
  `frame-ancestors`. A strict CSP (`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; frame-ancestors
  'none'`) costs nothing for this static app.

---

## 3. Third-party dependencies and malware analysis

| Check | Result |
|---|---|
| Sources | 630 lockfile packages: **606 from crates.io**, 24 workspace crates. No git dependencies, no `[patch]`/`[replace]`, no alternative registries. Every registry package has a lockfile checksum, and `cargo fetch --locked` verified all of them. |
| Build scripts (90) | Scanned for network access, process spawning, credential paths (`.ssh`, `.aws`, tokens), obfuscated blobs and home-directory access. Every hit is ordinary toolchain probing: `RUSTC_WRAPPER` invocations in `libc`/`rustix`/`getrandom`/`rustversion`, `strip` in `rav1e`/`av-scenechange`, `freebsd-version` in `libc`, and `ring`'s `nasm` (not compiled). Nothing downloads, writes outside `OUT_DIR` or reads secrets. |
| Proc macros (43) | All well known (serde, thiserror, zerocopy, zbus, wasm-bindgen, pin-project…). |
| Prebuilt binaries in crates | The `windows_*` import libraries (expected, the standard `windows-rs` approach), two small test DLLs in `libloading/tests` and `wit-bindgen`'s tiny `cabi_realloc` objects (the wasm32 component path). Nothing else. |
| Sockets in dependency code | Only in expected places: `x11rb` (X11 display connection), `zbus` (D-Bus for accessibility), `polling`/`async-io`, `rustls`, plus IP-address type helpers. No dependency makes HTTP requests. |
| Lesser-known crates | Checked on crates.io: `zcheapstr` (new, 2026-08, from the zbus maintainers' `z-galaxy` org), `no_std_io2`, `pastey`, `pxfm`, `polycool`, `zmij` (dtolnay), `simd_cesu8`, `float8`, `fax`, `presser`, `equator`, `typed-path`, `mintex`. All have public repositories with millions of downloads and plausible dependency paths. `zcheapstr` (282 lines, no `unsafe`, no I/O) was read in full. |
| Known advisories | 7 vulnerabilities and 2 warnings (§2 S3, S5, S10). Only `quick-xml` is exploitable in LightCraft. |
| Model weights | Loaded only from `.safetensors` through a custom reader with a 100 MB header cap and no `mmap` (`crates/segment/src/weights.rs`). No pickle/`.pt` loading, so a weight file can't execute code. |

**How malware could get in, and what stands in the way:**

1. **A compromised crate release on `cargo update`.** The lockfile pins exact versions and checksums, but nothing
   reviews updates. Add `cargo deny` (bans + sources + advisories) and consider `cargo vet` with imported audits
   from Mozilla, Google and others for the ~600 crates. Review `Cargo.lock` diffs in PRs.
2. **A build-script or proc-macro payload.** These run on developer machines and CI with full user privileges. In
   CI they run in the same job as the signing secrets (S4). Build in one job and sign in another that only receives
   the artifacts.
3. **Release tooling** (S4: action tags, `appimagetool`, NuGet, `nfpm`). This is the weakest link, because it adds
   code to shipped artifacts without going through Cargo's checksum chain at all.
4. **Model mirrors** (S5). Weights are hash-pinned; tokenizer files aren't yet.

---

## 4. Network traffic

### 4.1 Outbound connections the product can make

| # | Trigger | Destination | What is sent | What it reveals |
|---|---|---|---|---|
| N1 | User clicks **Download** for Object/Describe masks (or an agent calls `segment.model.download {acknowledged: true}`) | Mirrors from `LIGHTCRAFT_SAM3_MIRRORS`, `<settings>/models/sam3-mirrors.txt`, then `DEFAULT_MIRRORS` (**empty** at this commit, so no download without user configuration) | DNS lookup; TCP 443 (or 80 for an `http://` mirror); `GET <base>/{vocab.json, merges.txt, model.safetensors}` over HTTP/1.1 with `Host`, `User-Agent: LightCraft/0.2.1`, `Accept: */*`, `Accept-Encoding: identity`, `Connection: close`, optional `Range`, and `Authorization: Bearer $LIGHTCRAFT_SAM3_TOKEN` only on TLS to the configured host. About 3.44 GB. | IP address, app version, the fact you use SAM 3; to Hugging Face, also your account through the token |
| N2 | Help menu, About, Discord button, "Send Feedback…" | Opened in the **system browser** (`open`, `explorer`, `xdg-open`; https only): `github.com/storytold/lightcraft`, `getartcraft.com`, `discord.gg/artcraft` | Normal browser request | Browser-level only; LightCraft sends no data in the URL |
| N3 | **Show on Map** in the Metadata panel | `https://www.openstreetmap.org/?mlat=<lat>&mlon=<lon>#map=…` in the browser | Exact coordinates (6 decimals, about 10 cm) in the **query string** | The photo's location, sent to OSM's servers and logs (P3) |
| N4 | SAM 3 licence link | `github.com/facebookresearch/sam3` in the browser | none | — |

Nothing else in the product opens an outbound connection: no telemetry, update check, crash upload, licence check,
font or icon CDN, map tiles, or reverse geocoding.

### 4.2 Listeners and local IPC

| Component | Address | Default | Notes |
|---|---|---|---|
| Control server | `127.0.0.1:<PORT>` TCP | **off** (`--control` / `LIGHTCRAFT_CONTROL_PORT`) | No authentication (S1) |
| MCP server | stdio | on demand (`lightcraft-cli mcp`) | Headless; no socket |
| MCP connect mode | TCP client to `127.0.0.1:7980` | on demand (`--connect`) | Speaks the control protocol |
| Dev web server | `127.0.0.1:8080` | dev only (`cargo xtask web --serve`) | S7 |
| Desktop integration | D-Bus session/accessibility bus (AT-SPI through `accesskit`/`zbus`), X11/Wayland sockets, GPU drivers | always (Linux) | Standard; any process on the session bus can read UI text through the accessibility API |

### 4.3 Runtime verification

The binaries were built at this commit (debug profile, Linux x86_64) and run under `strace -f -e trace=%network`
with a fresh `$HOME`:

| Run | Network syscalls observed |
|---|---|
| `lightcraft-cli snapshot --demo -o snap.png` (headless UI, demo library) | **none** |
| `lightcraft-cli render snap.png -o out.jpg --set light.exposure=1` | **none** |
| `lightcraft-cli mcp --demo` (`initialize`, `tools/list`, `query_photos`) | **none** (stdio only) |
| `lightcraft --memory --control 18731` under Xvfb, driven for the S1 test | one `AF_INET` socket: `bind(127.0.0.1:18731)` + `listen` (the control server). `AF_UNIX` connects: 8× X11 display (`@/tmp/.X11-unix/X99`), 1× D-Bus session bus (`/run/user/0/bus`, accessibility). **No outbound `connect`, no DNS lookups.** |

The model download (N1) wasn't exercised: `DEFAULT_MIRRORS` is empty, and starting it needs a configured mirror and
explicit consent. Its traffic in §4.1 comes from reading `crates/fetch`.

### 4.4 Web build

The WASM build fetches only its own `lightcraft_web_bg.wasm`/JS from the hosting origin (`index.html`). `web-sys` is
compiled without `fetch`, `Request` or `WebSocket` bindings. Photos stay in the browser (OPFS + IndexedDB) and are
never uploaded. The model downloader is compiled out on wasm32. The host sees only ordinary static-file requests.

### 4.5 Build and development traffic (not the product)

`cargo` downloads from crates.io; `cargo xtask corpus --download` fetches CC0 raws from `raw.pixls.us` (no checksums;
dev-only); CI downloads rustup (`curl | sh` in `freebsd.yml`), `actionlint`, `nfpm`, `appimagetool`, the WiX
`dotnet` tool, the NuGet signing client and `craft-fonts`. The supply-chain notes are in S4.

---

## 5. Privacy assessment

**Strengths.** LightCraft is local-first. No account, cloud sync, telemetry, analytics, advertising identifiers,
crash reporting or update pings. The only optional network feature is explicit and documented, and the license
prompt runs before it. Face regions are read from XMP but never detected or computed by LightCraft, and they are not
written into exports. Permanent delete removes catalogue entries only, never originals.

**Concerns.**

- **P1 Location and metadata in exports (Medium).** `ExportOptions::default()` uses `MetadataPolicy::All` with
  `remove_location: false` (`crates/engine/src/export.rs:556`). Every exported JPEG therefore carries GPS
  coordinates, sublocation, city, state and country, plus caption, keywords (often people's names), capture time and
  camera/lens data. Confirmed in the S1 test: an `app.export` with default settings wrote the GPS coordinates into
  both EXIF and XMP. This matches Lightroom's defaults, but most people export to share.
  **Original and DNG exports ignore the metadata policy entirely.** Original copies the file byte for byte (with its
  embedded EXIF GPS) plus a full XMP sidecar, and DNG embeds the full sidecar packet including GPS
  (`PreparedExport::run`, `sidecar::sidecar_packet`). The dialog hides the metadata options for these formats, but
  an API/CLI/MCP caller that passes `removeLocation: true` with `format: "dng"` gets it **silently ignored**.
  *Suggest* defaulting "Remove Location Info" to on for new export presets, or warning when exporting geotagged
  photos; honouring `remove_location` in the DNG packet (and rejecting it for Original); and adding a "Remove Person
  Info" option that drops person keywords.
- **P2 AI agents (Medium, usage-dependent).** Through MCP, `screenshot`/`render` return photos as base64 images, and
  catalogue tools return file names, titles, captions, keywords and capture times. With a cloud-hosted model that
  content leaves the machine under the AI provider's terms. `docs/mcp.md` should say so plainly, and an "MCP: allow
  image content" / "redact location" switch would help.
- **P3 Show on Map (Low).** User-initiated and labelled ("Open the place in OpenStreetMap"). The coordinates sit in
  the query string, not the fragment, so they reach OSM's servers. Using only the fragment (`#map=15/lat/lon` still
  centres the map, without the marker) keeps them in the browser.
- **P4 Model download metadata (Low).** The mirror operator sees the IP address and `User-Agent: LightCraft/<version>`.
  With a Hugging Face mirror the token ties the download to an HF account.
- **P5 Data at rest (Low).** The catalogue (journal + snapshots), preview caches and `ui.json` are created with the
  process umask (usually world-readable on Linux/macOS multi-user systems) and aren't encrypted. They hold file
  paths, GPS, captions, people keywords and thumbnails. Creating the settings directory as `0700` is cheap. The
  library folder is the user's choice.

---

## 6. What the project already does well

- `#![forbid(unsafe_code)]` on every production crate; the single FFI call in `crates/sysmem` is documented and
  sound.
- Clippy denies `unwrap`/`expect`/`panic`/`todo`/`unreachable` in production code. Decoders, ICC parsing, merges and
  SAM jobs run under `catch_unwind`, behind a panic hook.
- Hostile-input discipline in the parsers: `get()` instead of indexing, checked arithmetic on dimensions
  (`ljpeg.rs`, `tiffraw.rs`), recursion limits (`MAX_DEPTH` in XMP, GPX, CR3 and Luminar), PNG/TIFF decoder limits,
  a 100 MB cap on safetensors headers.
- Control server: loopback-only bind, rejection of HTTP request lines, 4 MiB line cap, 16-connection cap.
- Downloader: SHA-256 and exact-size pinning for the weights, size caps for unpinned files, a redirect limit, a
  bearer token scoped to TLS and the original host, `.part` files with verification before the rename, no proxy
  support (no proxy-credential leaks), consent required.
- File-name templates strip separators, and folder templates reject `..`, absolute paths and drive letters
  (`rename.rs`). `check_write_target` stops exports and screenshots from overwriting originals.
- CI defaults to `contents: read`; the signing secrets are confined to the `release` environment and branch;
  `craft-fonts` is pinned by commit.
- Model weights are safetensors only (no pickle), and the license is acknowledged before download.

## 7. Prioritised recommendations

1. **S1:** token-authenticate the control channel (or use a `0600` Unix socket), and stop taking `app` from
   requests in `photo.editInExternal`.
2. **S2:** replace `cmd /C start` with `explorer.exe`/`ShellExecuteW`; add a regression test with `&` in a file name.
3. **S3:** bump `quick-xml` to 0.41; use `with_checks(false)` in `xmp_merge::scan`; cap sidecar size.
4. **S4:** pin actions by SHA in `release.yml`; pin and checksum `appimagetool`, the NuGet signing client and
   `nfpm`; add `cargo audit`/`cargo deny` to `cargo xtask ci` and a weekly workflow; split signing into its own job.
5. **S5:** pin the tokenizer hashes; refuse HTTPS→HTTP redirects; plan a way off `rustls-rustcrypto` alpha.
6. **P1:** default to removing location on export, or warn when exporting geotagged photos.
7. **S6:** cap inflated ZIP totals and the default decode megapixels.
8. **S7–S11, P2–P5:** as described above.

## Appendix A: `cargo audit` output (2026-10-08)

```
Loaded 1294 security advisories
Scanning Cargo.lock for vulnerabilities (630 crate dependencies)
quick-xml      0.38.4   RUSTSEC-2026-0194  Quadratic run time when checking a start tag for duplicate attribute names (7.5)  → >=0.41.0
quick-xml      0.38.4   RUSTSEC-2026-0195  Unbounded namespace-declaration allocation in NsReader (7.5)                     → >=0.41.0
rsa            0.9.10   RUSTSEC-2023-0071  Marvin Attack: potential key recovery through timing sidechannels (5.9)         → no fix
rustls-webpki  0.102.8  RUSTSEC-2026-0099  Name constraints were accepted for certificates asserting a wildcard name     → >=0.103.12
rustls-webpki  0.102.8  RUSTSEC-2026-0104  Reachable panic in certificate revocation list parsing                       → >=0.103.13
rustls-webpki  0.102.8  RUSTSEC-2026-0098  Name constraints for URI names were incorrectly accepted                      → >=0.103.12
rustls-webpki  0.102.8  RUSTSEC-2026-0049  CRLs not considered authoritative by Distribution Point                       → >=0.103.10
paste          1.0.15   RUSTSEC-2024-0436  unmaintained (warning)
ttf-parser     0.25.1   RUSTSEC-2026-0192  unmaintained (warning)
error: 7 vulnerabilities found!
```

`rsa` and `rustls-webpki 0.102.8` come only through `rustls-rustcrypto` (`lightcraft-fetch`). Reachability for each
is analysed in S3 and S5.

## Appendix B: reproducing the XMP merge slowdown

Build a binary that depends on `lightcraft-meta` (path dependency, this repository's `Cargo.lock`) and time
`lightcraft_meta::merge_xmp(old, fresh, rules)`, where `old` is
`<x:xmpmeta …><rdf:RDF …><rdf:Description rdf:about="" a0="" a1="" … a{N-1}=""/></rdf:RDF></x:xmpmeta>` and `fresh`
is any small valid packet. Time grows with N².
