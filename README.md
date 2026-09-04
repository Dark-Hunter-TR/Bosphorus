# Bosphorus

**A self-learning DPI (Deep Packet Inspection) bypass engine for Windows.**
Bosphorus captures outbound TLS handshakes with WinDivert, automatically discovers
which packet-manipulation strategy defeats the censor on *your* network for *each*
site, locks that strategy in, and remembers it per network — with zero manual
tuning.

*Kendi kendine öğrenen, Windows için DPI (Derin Paket İncelemesi) atlatma motoru.*

---

**Language / Dil:** [English](#english) · [Türkçe](#türkçe)

> ⚠️ **Legal note / Yasal not.** Bosphorus is a network-research and
> censorship-circumvention tool. Use it only on networks and traffic you are
> authorised to test. You are responsible for complying with the laws and
> regulations that apply to you.
>
> Bosphorus bir ağ araştırma ve sansür atlatma aracıdır. Yalnızca test etme
> yetkiniz olan ağlarda ve trafikte kullanın. Size uygulanan yasa ve
> düzenlemelere uymaktan siz sorumlusunuz.

---

# English

## Table of contents

- [What Bosphorus is](#what-bosphorus-is)
- [How it works](#how-it-works)
  - [The capture path](#the-capture-path)
  - [Connection tracking & verdicts](#connection-tracking--verdicts)
  - [The discovery lifecycle](#the-discovery-lifecycle)
  - [Per-network memory (NetKey)](#per-network-memory-netkey)
  - [Live network switching](#live-network-switching)
- [The evasion toolbox](#the-evasion-toolbox)
- [The discovery grid](#the-discovery-grid)
- [Project layout](#project-layout)
- [Requirements](#requirements)
- [Building from source](#building-from-source)
- [Command-line usage](#command-line-usage)
  - [`--strategy` grammar](#--strategy-grammar)
- [Running as a Windows Service](#running-as-a-windows-service)
- [Files, folders & logs](#files-folders--logs)
- [Safety & design decisions](#safety--design-decisions)
- [Limitations & out of scope](#limitations--out-of-scope)
- [Credits & attribution](#credits--attribution)
- [License](#license)

## What Bosphorus is

Many networks run a middlebox that inspects the plaintext **SNI** (server name) in
the TLS `ClientHello` and drops or resets connections to blocked hosts. Tools such
as **GoodbyeDPI** and **zapret** defeat this by splitting, reordering, or
shadowing that first packet so the middlebox never sees a clean SNI while the real
server still does.

Those tools work well, but they expect you to pick a strategy (`--fake-tls`,
`--frag-by-sni`, `--wrong-seq`, a TTL value, …) and hope it fits your ISP.
Bosphorus removes that step:

- It watches whether a site actually gets blocked (a DPI `RST`, a blackhole).
- If it does, it **sweeps a grid of ~166 strategies** for that specific host,
  running several candidates in parallel across concurrent connections.
- When a *single* candidate produces a real `ServerHello` twice in a row (its
  own successes — a different candidate succeeding in a parallel connection does
  not count), it is **promoted** and used for every later connection to that host.
- The result is **saved to disk, keyed by the network you were on**, so the next
  time you join that Wi-Fi / LAN the learned strategies are already in place.

It is a Rust workspace: a portable core engine, a thin WinDivert wrapper, and a
CLI that can also install itself as a Windows Service.

## How it works

```
                 ┌──────────────────────── bosphorus-cli ───────────────────────┐
   Wire  ─────▶  │  WinDivert  ─▶  PacketSource  ─▶  ┌───────────────────────┐   │
   (:443 TLS)    │                                   │   bosphorus-core      │   │
                 │                                   │                       │   │
                 │                                   │  conntrack ─▶ verdict │   │
                 │                                   │       │               │   │
                 │                                   │       ▼               │   │
                 │                                   │  discovery (grid)     │   │
                 │                                   │       │  picks a      │   │
                 │                                   │       ▼  Strategy     │   │
   Wire  ◀─────  │  WinDivert  ◀─  PacketSink   ◀─   │  transforms ─▶ batch  │   │
                 │                                   └───────────┬───────────┘   │
                 │                                               ▼               │
                 │                        profile JSON  ◀──  persist (per NetKey) │
                 └──────────────────────────────────────────────────────────────┘
```

### The capture path

A single WinDivert handle at the `NETWORK` layer captures a deliberately narrow
slice of traffic (filter fragments taken verbatim from GoodbyeDPI):

- **Outbound** TCP to port **443** that looks like a request or a TLS handshake
  (payload `< 1200` bytes, or starts with `GET `/`POST`, or a TLS record header).
- **Inbound** from port 443 that carries a verdict signal: the `SYN`+`ACK`
  (its TTL tells us the server's stack and hop count), a `RST`, or the first data
  segment that begins with `0x16` (a `ServerHello`).
- Loopback and RFC 1918 / link-local ranges are excluded on both sides.

Everything else on the machine is untouched. Non-IP and non-TCP packets pass
straight through. The per-packet loop body runs inside `catch_unwind`, so a single
malformed packet degrades to one log line rather than killing the process.

### Connection tracking & verdicts

Every captured packet updates a per-flow state machine keyed by the 5-tuple. When
the outcome becomes certain the flow is classified:

| Verdict        | Meaning                                                            |
|----------------|-------------------------------------------------------------------|
| `Success`      | The handshake got through **and held** — either real inbound application data flowed, or a short grace window elapsed after the `ServerHello` with no teardown. |
| `DpiReset`     | A `RST` came from the server after our `ClientHello`, before any `ServerHello` — the classic in-path reset. |
| `LateReset`    | The `ServerHello` got through, then a `RST` / fatal TLS alert tore the flow down inside the grace window — a "delayed reset" DPI. Scored as a failure. |
| `Blackhole`    | `ClientHello` sent, nothing came back (retransmits, then timeout). |
| `TlsError`     | A failure during setup that is not a clean DPI reset.            |
| `Inconclusive` | The flow aged out before anything decisive happened.            |

`Success` is deferred by a ~1 s grace window (`ConntrackTuning::app_grace`, always
shorter than the blackhole timeout) so a censor that passes the `ServerHello` and
then resets the flow is caught as `LateReset` rather than banked as a success.
Real inbound application data short-circuits the wait. Verdicts that need a timer
(the grace window, blackhole, aged-out flows) are resolved on a ~2 Hz maintenance
tick, then fed back to discovery just like live ones.

### The discovery lifecycle

Discovery is **per target**, where a *target* is the lowercased SNI host. A
`ClientHello` with no readable SNI (already fragmented, or ECH) is never mutated
and never becomes a target.

```
  ┌─────────┐   first ClientHello passes through unchanged
  │  Probe  │   ── Success ──▶ Active (passthrough is fine, nothing to do)
  └────┬────┘
       │ DpiReset / Blackhole
       ▼
  ┌──────────┐  sweep the grid; concurrent connections take different
  │ Discover │  candidates in parallel (tracked as "in-flight")
  └────┬─────┘
       │ one candidate gets 2 of its own Successes in a row
       ▼
  ┌─────────┐   that Strategy is locked in and used for every later
  │ Active  │   connection to this host
  └────┬────┘
       │ the active Strategy fails 3× in a row
       ▼   (demoted — discovery restarts for this target)
  ┌───────────┐  every candidate tried, none worked
  │ Exhausted │  (revives automatically if the grid later grows)
  └───────────┘
```

- **Parallel sweep.** Two connections opening at once to the same blocked host
  are handed *different* untried candidates, so the sweep goes as fast as the app
  retries. An in-flight candidate that never resolves stops blocking the sweep
  after 15 s. The "2 Successes in a row" promotion count is kept **per
  candidate**, so two different candidates each succeeding once in parallel do
  not add up to a promotion.
- **Retransmit-aware.** Once a strategy has been emitted for a flow, a later
  `ClientHello` on that same flow is a retransmit and is forwarded untouched — no
  amplification.
- **Transient failures are forgiven once.** A `DpiReset` (a deliberate middlebox
  reset) rules a candidate out immediately, but a `Blackhole` — which can be
  momentary packet loss — is retried once before the candidate is parked. A
  trial-count ceiling (`grid size × 2`) still forces the sweep to `Exhausted`
  even if forgiven candidates would otherwise keep it going.
- **Grid revival.** A target that exhausted, say, a 154-strategy grid and is
  later loaded under a 166-strategy grid re-enters `Discover` and tries only the
  new candidates — the old `tried` list is preserved.
- **Eviction.** Idle `Probe` / passthrough targets are dropped after 24 h, any
  target after 7 d, and a hard cap of 4096 targets is enforced worst-value-first.
  This keeps a 24/7 run from growing one record per hostname ever contacted.

### Per-network memory (NetKey)

Learned state is persisted as one JSON file per network. The **NetKey** is
`gateway IPv4 + subnet CIDR + primary DNS suffix`, hashed to a short hex stem. The
gateway adapter is chosen via `GetBestInterface` toward `8.8.8.8`, so a Hamachi /
VPN / Radmin virtual adapter that merely sorts first in the list does not poison
the key.

- The profile records, per target: phase, the `tried` list, per-candidate
  success/trial counts, the promoted strategy, and the server's guessed initial
  TTL.
- **Only targets worth re-learning are written**: a `Discover` sweep in
  progress, an `Active` target with a promoted strategy, or an `Exhausted` one.
  Hosts that were never blocked (probe succeeded) are *not* persisted — they
  need no strategy and are re-established for free on the next connection, so
  they would only bloat the file.
- A **grid signature** (FNV-1a over every candidate id) is stored too. If the
  grid changed between builds, stale entries degrade gracefully to "keep only the
  learned TTL" instead of trusting renumbered ids.
- Writes are throttled (every 30 s) and also happen on a clean shutdown.
- If the fingerprint can't be read, the key is `nonet` and that session is kept
  **in memory only** — a failed probe on an unknown network never pollutes a real
  network's file.
- **A network's profile is never deleted.** Each NetKey's file is only ever
  created or overwritten in place with that same network's newer state (atomic
  temp-file + rename). Switching networks flushes the old network's file and
  loads the new one's — it never touches, merges, or removes any other
  network's file. Roam between home, office, and a phone hotspot for months and
  every network keeps its own learned strategies intact.

### Live network switching

When you roam Wi-Fi, toggle a VPN, or renew DHCP, a Windows route-change / address
-change callback arms a re-check. On the next maintenance tick, after a 5 s
debounce and no more often than every 30 s, Bosphorus recomputes the NetKey. If it
changed it:

1. flushes the old network's learned state to that network's own file,
2. builds a fresh session for the new network (loading its file if it exists),
3. swaps it in atomically, and
4. clears stale connection-tracking state.

No restart, no dropped capture.

## The evasion toolbox

A `Strategy` is a recipe applied to one `ClientHello`. It is built from these
pieces:

**Fake / desync packet** — an extra packet sent alongside the real one that the
middlebox accepts but the server discards:

| Method            | What it does                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `WrongSeq`        | Fake with `SEQ`/`ACK` shifted into the past (GoodbyeDPI's `-10000` / `-66000`). |
| `WrongChecksum`   | Fake with a deliberately corrupted TCP checksum.                            |
| `TtlLimited`      | Fake with a low TTL so it expires before it reaches the server.            |
| `SeqPlusTtl`      | `WrongSeq` + low TTL.                                                       |
| `ChecksumPlusTtl` | `WrongChecksum` + low TTL.                                                  |
| `OverlapDisorder` | No separate fake: the real segments are sent reversed, and the second one is prefixed with `seqovl` junk bytes (zapret's `disorder` + `seqovl`). Opt-in only. |

**Fragmentation** — split the TCP payload at one or more anchors:

- `AbsoluteOffset(n)` — a fixed byte offset.
- `TlsRecordStart` — right after the 5-byte TLS record header.
- `SniStart` — right before the SNI host name (`--frag-by-sni`).
- `SniMiddle` — inside the SNI host name.
- Multiple anchors → multiple segments. Optional `reverse` sends the last
  segment first.

**Fake payload** — GoodbyeDPI's verbatim 517-byte static `ClientHello`, or an
"aggressive" variant with extra RFC 7685 padding to push a middlebox's reassembly
buffer past its limit.

**TTL policy** — a fixed user value, or an auto-heuristic
`clamp(hops_to_server − 4, 3, 10)` seeded from the `SYN`+`ACK` hop count.

**TLS padding (`tls_pad`)** — an RFC 7685 padding extension added to the
`ClientHello` *before* fragmenting, so the record grows past whatever fixed buffer
the DPI's reassembly allocates.

**Send order** — fake-then-real or real-then-fake. **Repeats** — send the fake N
times (GoodbyeDPI's `--fake-resend`).

**Server-stack gating.** `OverlapDisorder` feeds the server junk bytes and only
works against a *last-received-wins* stack. Bosphorus reads the server's initial
TTL from the `SYN`+`ACK` (64 = Linux/unix, 128 = Windows, 255) and never hands an
overlap candidate to a Windows / first-received-wins server.

## The discovery grid

The default grid is **166 strategies**, ordered roughly by how often each tends to
work so the cheap wins come first:

| Family                        | Count | Notes                                             |
|-------------------------------|-------|--------------------------------------------------|
| Single-split fragment + fake  | 142   | 7 anchors × {forward, reverse} × 6 desync kinds × {1, 2} repeats, de-duplicated. |
| Multi-part native fragment    | 12    | 3 curated cut patterns × {forward, reverse} × {no fake, wrong-seq}. |
| RFC 7685 `tls_pad`            | 6     | 3 anchors × {wrong-seq, wrong-checksum}, 512-byte pad. |
| "Aggressive" fake             | 6     | Bigger padded fake × 3 anchors × {wrong-seq, wrong-checksum}. |
| `OverlapDisorder`             | +8    | **Only** with `--enable-overlap` → 174 total. 4 anchors × 2 `seqovl`. |

`bosphorus --engine --strategy list` prints the exact grid for your build.

## Project layout

Cargo workspace, three crates:

| Crate               | Role                                                                       |
|---------------------|--------------------------------------------------------------------------|
| `bosphorus-core`    | The engine: packet parsing, connection tracking, the strategy model, the generator grid, the discovery scheduler, per-network persistence. **Platform-agnostic** — no dependency on WinDivert or the `windows` crate. Talks to the network through `PacketSource` / `PacketSink` traits. |
| `bosphorus-divert`  | A thin, allocation-free **safe wrapper around WinDivert 2.2** via the `windivert-sys` FFI (`WinDivertOpen`/`Recv`/`Send`/`CalcChecksums`/`SetParam`/`Shutdown`/`Close`, plus filter compilation). |
| `bosphorus-cli`     | The `bosphorus` binary. Wires the WinDivert backend into the core engine, adds the Windows Service host, the NetKey computation, the route-change watcher, structured logging, the Event Log provider, and a small hand-rolled EN/TR message catalog. |

## Requirements

- **Windows x64.** The driver wrapper is `#![cfg(windows)]`.
- **Administrator rights** for anything that opens the WinDivert driver
  (`--engine`, `--selftest`, `--passthru`, `--observe`, `service install`).
  `--check-filters`, `--discovery-demo`, `--mem-bench` and `service status` need
  no elevation.
- **The WinDivert 2.2.2 driver must be able to load.** HVCI / Memory Integrity,
  Smart App Control, or a WDAC policy can block an unsigned-in-their-eyes driver
  **silently at boot**. `service install` pre-flights the driver load and refuses
  (or warns, with `--force`) if it can't.
- **A stable path for the executable.** WinDivert registers the driver from the
  path the `.sys` file sits at; if you later move `bosphorus.exe` the service (and
  the driver) break. Keep it somewhere like `C:\Program Files\Bosphorus\`, or use
  `service install --install-dir`.
- **Rust** (stable, ≥ 1.80) with the `x86_64-pc-windows-msvc` target, to build
  from source.

## Building from source

1. **Get the WinDivert 2.2.2 binaries.** Download the official
   `WinDivert-2.2.2-A.zip` from the `basil00/WinDivert` v2.2.2 release and unpack
   it so that this path exists:

   ```
   assets/WinDivert-2.2.2-A/x64/WinDivert.dll
   assets/WinDivert-2.2.2-A/x64/WinDivert64.sys
   assets/WinDivert-2.2.2-A/x64/WinDivert.lib
   ```

   `assets/` is git-ignored. `.cargo/config.toml` points `WINDIVERT_PATH` at that
   folder (a relative path resolved from the workspace root); if your Cargo is old
   enough that `relative = true` misbehaves, set an absolute path there instead.

2. **Build.**

   ```powershell
   cargo build --release                 # day-to-day optimized build
   cargo build --profile release-dist    # the shipped artifact: fat LTO, stripped
   ```

   `bosphorus-divert`'s build script stages `WinDivert.dll` and `WinDivert64.sys`
   next to `bosphorus.exe` **and** next to the test binaries, so `cargo test` and
   a bare `cargo run` both find the driver.

3. **Test.**

   ```powershell
   cargo test                            # unit + integration tests (no elevation)
   ```

   > **Build profiles keep `panic = "unwind"` on purpose.** The clean shutdown
   > path (SCM `SERVICE_STOPPED`, the final profile flush, `WinDivertClose` in a
   > `Drop`) all runs during unwinding. Do not switch to `panic = "abort"`.

## Command-line usage

```
bosphorus <command> [options]
```

| Command                                   | Elevation | What it does                                                              |
|-------------------------------------------|:---------:|------------------------------------------------------------------------|
| `--engine [--secs N] [--strategy S] [--enable-overlap]` | yes | Run the engine. With no `--strategy`, this is full **auto-discovery** with per-network persistence and live network-switch handling. With `--strategy`, it forces one fixed strategy (network-independent, not persisted). `--secs N` stops automatically after N seconds; otherwise `Ctrl+C`. |
| `--check-filters`                         | no        | Build the WinDivert filter strings and syntax-check them against `WinDivertHelperCompileFilter`. |
| `--discovery-demo [--fresh]`              | no        | A no-driver proof that the discovery loop runs and that sweep progress survives across processes. `--fresh` wipes the demo profile first. |
| `--mem-bench [N]`                         | no        | Drive the engine with `N` synthetic targets (default 2000) and print the RAM footprint. |
| `--observe [--secs N]`                    | yes       | Analysis only. Sniffs **all** TCP + UDP on all ports, mutates nothing, and prints a per-target profile table (SNI / IP, port, protocol, rough outcome). Built for inspecting what an app like the Discord desktop client actually does. |
| `--passthru [--secs N]`                   | yes       | Capture every `:443` TCP packet, log it, and reinject it **unchanged** — the "the internet still works" smoke test. |
| `--selftest`                              | yes       | The WinDivert verification harness (V1–V4): new-flow first segments, `ClientHello` sizes, wrong-checksum survival, driver load + version. |
| `--selftest-m7`                           | yes       | Overlap / disorder feasibility probes (V-A / V-B / V-C). |
| `service <install\|uninstall\|run\|status>` | varies | See [Running as a Windows Service](#running-as-a-windows-service). |

**Language.** Messages on the `--engine` path and the service commands are English
by default, or Turkish if the Windows UI language is Turkish. Override with
`--lang en|tr` or the `BOSPHORUS_LANG` environment variable. Developer `tracing`
output and the diagnostic sub-commands stay English.

**Log verbosity.** Set `RUST_LOG`, e.g.
`RUST_LOG=bosphorus::discovery=info,bosphorus::strategy=info,bosphorus::conntrack=info`.
`bosphorus::mem=debug` turns on the periodic footprint digest.

### `--strategy` grammar

```
--strategy list                       print the default grid, one per line
--strategy grid:<i>                    run grid entry number <i>
--strategy overlap:<seqovl>/<anchor>   forced OverlapDisorder (disorder + seqovl)
--strategy <frag>[/<desync>]           build a strategy by hand
```

- `<frag>` = one anchor, or a comma-joined list for a multi-part split, or `none`.
  An anchor is `<u16>` (absolute offset) | `sni` | `sni-mid` | `tls`.
- `<desync>` = `wrongseq` (default) | `wrongsum` | `ttl:<u8>` | `none`.
- Append `+pad:<n>` to any form to force an RFC 7685 `tls_pad` of `n` bytes.

Examples:

```powershell
bosphorus --engine --strategy sni                 # split right before the SNI, wrong-seq fake
bosphorus --engine --strategy tls,sni             # 3-way split: record header | body | SNI onward
bosphorus --engine --strategy 2/wrongsum          # split at offset 2, corrupted-checksum fake
bosphorus --engine --strategy sni-mid/ttl:6       # split inside the SNI, TTL-6 fake
bosphorus --engine --strategy 2/wrongseq+pad:512  # + a 512-byte TLS padding extension
bosphorus --engine --strategy overlap:16/sni --enable-overlap
bosphorus --engine --strategy grid:0              # whatever the first grid entry is
```

## Running as a Windows Service

```powershell
# Install: creates the "Bosphorus" service (LocalSystem, delayed auto-start,
# restart-on-failure) and starts it. Pre-flights the WinDivert driver load.
bosphorus service install [--lang en|tr] [--enable-overlap]
                          [--profile-dir <path>] [--install-dir <path>]
                          [--start auto|demand] [--force]

bosphorus service status         # no elevation; also prints the newest profile file's age
bosphorus service uninstall [--purge]   # --purge also deletes %ProgramData%\Bosphorus
bosphorus service run            # SCM entry point only — not for interactive use
```

- `--install-dir` copies `bosphorus.exe`, `WinDivert.dll` and `WinDivert64.sys`
  into a stable folder and registers the service from the copy.
- The installer prints a block of PowerShell commands to **verify the service and
  driver actually came up** (`Get-Service Bosphorus`, the CodeIntegrity event log,
  the HVCI state, the profile files). Run them — a boot-time driver block is
  invisible otherwise.
- The service runs the same auto-discovery engine as `--engine` with no
  `--strategy`: per-network persistence under `%ProgramData%\Bosphorus\profiles`,
  the route-change watcher, and structured file logging under
  `%ProgramData%\Bosphorus\logs`. Lifecycle events also go to the Windows
  **Application** event log under provider name `Bosphorus`.

## Files, folders & logs

| Path                                         | What                                                    |
|----------------------------------------------|--------------------------------------------------------|
| `assets/WinDivert-2.2.2-A/x64/`              | The WinDivert runtime files you supply at build time.  |
| `%LOCALAPPDATA%\Bosphorus\profiles\*.json`   | Learned discovery profiles for an **interactive** `--engine` run — one per NetKey. |
| `%ProgramData%\Bosphorus\profiles\*.json`    | Same, for the **service** (SYSTEM can't use `%LOCALAPPDATA%`). |
| `%ProgramData%\Bosphorus\logs\`              | Rotating service log files.                            |

**Store resolution.** `--profile-dir DIR`, when given, is used verbatim. Otherwise
an interactive `--engine` uses the service's `%ProgramData%` store **if the
service is installed and already has a profile for the current network**
("service = authority"), so the two run modes share one per-network memory;
failing that it uses the per-user `%LOCALAPPDATA%` store as before. The write is
an atomic last-writer-wins replace with a per-process staging file — running the
service and a long interactive `--engine` against the same store at once won't
corrupt it, but they can overwrite each other's incremental learning (the
profile is a cache, not a ledger).
| Windows Application event log, provider `Bosphorus` | Service start / stop / open-failure / panic breadcrumbs. |

Inspect a running instance:

```powershell
Get-Service Bosphorus
Get-WinEvent -ProviderName Bosphorus
Get-ChildItem "$env:ProgramData\Bosphorus\profiles\*.json" | Select Name, LastWriteTime
```

## Safety & design decisions

- **The internet must keep working.** `Probe` sends the first `ClientHello`
  untouched. Non-IP / non-TCP traffic is never inspected. A `ClientHello` with no
  readable SNI is never mutated. `--passthru` exists as a standing proof that
  capture + reinjection is transparent.
- **`OverlapDisorder` is opt-in.** It can wedge a handshake against a
  first-received-wins server, so auto-discovery never sweeps it unless you pass
  `--enable-overlap`; even then it is gated away from Windows-stack servers.
- **`panic = "unwind"` is load-bearing** (clean SCM stop, final profile flush,
  `WinDivertClose` in `Drop`). The per-packet loop is wrapped in `catch_unwind`.
- **Verbatim third-party bytes are marked as such.** The WinDivert filter
  fragments and the 517-byte fake `ClientHello` are copied byte-for-byte from
  GoodbyeDPI and annotated not to be "tidied". The one deliberate exception is the
  "aggressive" fake, which is the static fake plus extra RFC 7685 padding built at
  call time.
- **Bounded memory for 24/7 runs.** Target eviction, the 4096 hard cap, and
  `TargetState::compact()` on terminal transitions keep the footprint flat; the
  `bosphorus::mem` digest lets you watch it.

## Limitations & out of scope

- **Windows only**, x64, TLS-over-TCP on port 443 only. Plain HTTP and non-443
  TLS are not handled by the engine.
- **QUIC / HTTP-3.** A QUIC-drop WinDivert filter is defined and compile-checked
  (`--check-filters`), but the dedicated `DROP` handle is not yet opened by the
  running engine, so QUIC is currently passed through. Where a censor blocks the
  SNI over QUIC too, a browser may still fail on those sites until it falls back
  to TCP.
- **DNS.** `EvasionConfig` has a `dns_upstream` field and the filter builder can
  add a `udp/53` clause, but DNS redirection is not wired into the CLI yet; DNS
  poisoning is only observable, not corrected.
- **IP-layer fragmentation** was analysed and deliberately shelved (blackhole
  risk, unverified on Windows).
- **Domain fronting / SNI spoofing** is out of scope — it needs client
  cooperation that packet manipulation alone can't provide.
- **ECH (Encrypted Client Hello).** With no plaintext SNI there is nothing to
  key discovery on; such handshakes are passed straight through.

## Credits & attribution

- **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** by ValdikSS — the
  WinDivert filter fragments and the static fake `ClientHello` are used verbatim;
  the fake-packet desync methods (`--wrong-seq`, `--wrong-chksum`, `--fake-resend`,
  `--frag-by-sni`, `--reverse-frag`) are modelled on it.
- **[zapret](https://github.com/bol-van/zapret)** by bol-van — the `disorder` +
  `seqovl` overlap technique and the auto-TTL heuristic shape.
- **[WinDivert](https://github.com/basil00/WinDivert)** by basil00 — the packet
  capture/injection driver. Bundled separately under its own license.
- The `windivert-sys` crate for the FFI bindings.

## License

Dual-licensed under **MIT OR Apache-2.0**, at your option (as declared in
`Cargo.toml`). WinDivert is distributed under its own terms — see
`assets/WinDivert-2.2.2-A/LICENSE`.

---

# Türkçe

## İçindekiler

- [Bosphorus nedir](#bosphorus-nedir)
- [Nasıl çalışır](#nasıl-çalışır)
  - [Yakalama yolu](#yakalama-yolu)
  - [Bağlantı takibi ve kararlar](#bağlantı-takibi-ve-kararlar)
  - [Keşif yaşam döngüsü](#keşif-yaşam-döngüsü)
  - [Ağ bazında hafıza (NetKey)](#ağ-bazında-hafıza-netkey)
  - [Canlı ağ değişimi](#canlı-ağ-değişimi)
- [Atlatma araç kutusu](#atlatma-araç-kutusu)
- [Keşif gridi](#keşif-gridi)
- [Proje yapısı](#proje-yapısı)
- [Gereksinimler](#gereksinimler)
- [Kaynaktan derleme](#kaynaktan-derleme)
- [Komut satırı kullanımı](#komut-satırı-kullanımı)
  - [`--strategy` dilbilgisi](#--strategy-dilbilgisi)
- [Windows Hizmeti olarak çalıştırma](#windows-hizmeti-olarak-çalıştırma)
- [Dosyalar, klasörler ve günlükler](#dosyalar-klasörler-ve-günlükler)
- [Güvenlik ve tasarım kararları](#güvenlik-ve-tasarım-kararları)
- [Sınırlamalar ve kapsam dışı](#sınırlamalar-ve-kapsam-dışı)
- [Teşekkürler ve atıf](#teşekkürler-ve-atıf)
- [Lisans](#lisans)

## Bosphorus nedir

Birçok ağ, TLS `ClientHello` içindeki açık **SNI** (sunucu adı) alanını inceleyen
ve engelli sitelere giden bağlantıları düşüren ya da sıfırlayan bir ara kutu
(middlebox) çalıştırır. **GoodbyeDPI** ve **zapret** gibi araçlar bu ilk paketi
bölerek, sırasını değiştirerek veya gölgeleyerek ara kutunun temiz bir SNI
görmesini engeller; gerçek sunucu ise handshake'i normal şekilde alır.

Bu araçlar iyi çalışır ama bir strateji seçmenizi (`--fake-tls`, `--frag-by-sni`,
`--wrong-seq`, bir TTL değeri, …) ve onun ISS'nize uymasını ummanızı bekler.
Bosphorus bu adımı ortadan kaldırır:

- Bir sitenin gerçekten engellenip engellenmediğini izler (DPI `RST`'i, karadelik).
- Engelleniyorsa, o siteye özel olarak **~166 stratejilik bir gridi tarar** ve
  eşzamanlı bağlantılar üzerinden birden fazla adayı paralel dener.
- *Tek bir* aday üst üste iki kez kendi başarısıyla gerçek bir `ServerHello`
  ürettiğinde (paralel bir bağlantıda başka bir adayın başarması sayılmaz) o
  strateji **terfi ettirilir** ve o siteye açılan sonraki tüm bağlantılarda
  kullanılır.
- Sonuç **o an bağlı olduğunuz ağa göre anahtarlanarak diske kaydedilir**; o
  Wi-Fi / yerel ağa bir dahaki katıldığınızda öğrenilen stratejiler zaten hazırdır.

Bir Rust workspace'idir: taşınabilir bir çekirdek motor, ince bir WinDivert
sarmalayıcısı ve kendini Windows Hizmeti olarak da kurabilen bir CLI.

## Nasıl çalışır

```
                 ┌──────────────────────── bosphorus-cli ───────────────────────┐
  Kablo ─────▶   │  WinDivert  ─▶  PacketSource  ─▶  ┌───────────────────────┐   │
  (:443 TLS)     │                                   │   bosphorus-core      │   │
                 │                                   │                       │   │
                 │                                   │  conntrack ─▶ karar   │   │
                 │                                   │       │               │   │
                 │                                   │       ▼               │   │
                 │                                   │  keşif (grid)         │   │
                 │                                   │       │  bir         │   │
                 │                                   │       ▼  Strategy     │   │
  Kablo ◀─────   │  WinDivert  ◀─  PacketSink   ◀─   │  dönüşümler ─▶ yığın  │   │
                 │                                   └───────────┬───────────┘   │
                 │                                               ▼               │
                 │                        profil JSON  ◀──  kalıcılaştır (NetKey) │
                 └──────────────────────────────────────────────────────────────┘
```

### Yakalama yolu

`NETWORK` katmanındaki tek bir WinDivert tanıtıcısı, bilinçli olarak dar bir
trafik dilimini yakalar (filtre parçaları GoodbyeDPI'dan bire bir alınmıştır):

- **443** portuna giden, istek ya da TLS handshake'ine benzeyen **giden** TCP
  (yük `< 1200` bayt, ya da `GET `/`POST` ile başlıyor, ya da bir TLS kayıt
  başlığı).
- 443 portundan gelen ve bir karar sinyali taşıyan **gelen** trafik: `SYN`+`ACK`
  (TTL'i sunucunun ağ yığınını ve atlama sayısını söyler), bir `RST`, ya da
  `0x16` ile başlayan ilk veri segmenti (bir `ServerHello`).
- Loopback ve RFC 1918 / link-local aralıkları her iki yönde de dışlanır.

Makinedeki diğer her şeye dokunulmaz. IP olmayan ve TCP olmayan paketler doğrudan
geçer. Paket başına döngü gövdesi `catch_unwind` içinde çalışır; bozuk tek bir
paket süreci öldürmek yerine tek satırlık bir günlüğe düşer.

### Bağlantı takibi ve kararlar

Yakalanan her paket, 5'li demetle (5-tuple) anahtarlanan akış bazında bir durum
makinesini günceller. Sonuç kesinleştiğinde akış sınıflandırılır:

| Karar          | Anlamı                                                                |
|----------------|---------------------------------------------------------------------|
| `Success`      | Handshake geçti **ve tuttu** — ya gerçek gelen uygulama verisi aktı, ya da `ServerHello` sonrası kısa bir bekleme penceresi teardown olmadan doldu. |
| `DpiReset`     | `ClientHello`'muzdan sonra, herhangi bir `ServerHello` gelmeden sunucudan bir `RST` geldi — klasik yol-içi sıfırlama. |
| `LateReset`    | `ServerHello` geçti, ardından bekleme penceresi içinde bir `RST` / ölümcül TLS alert bağlantıyı kopardı — "gecikmeli sıfırlama" DPI'ı. Başarısızlık sayılır. |
| `Blackhole`    | `ClientHello` gönderildi, hiçbir yanıt gelmedi (yeniden iletimler, ardından zaman aşımı). |
| `TlsError`     | Kurulum sırasında temiz bir DPI sıfırlaması olmayan bir hata.       |
| `Inconclusive` | Belirleyici bir şey olmadan akış zaman aşımına uğradı.             |

`Success` ~1 sn'lik bir bekleme penceresiyle (`ConntrackTuning::app_grace`, her
zaman karadelik zaman aşımından kısa) ertelenir; böylece `ServerHello`'yu geçirip
sonra bağlantıyı sıfırlayan bir sansür, başarı olarak kaydedilmek yerine
`LateReset` olarak yakalanır. Gerçek gelen uygulama verisi beklemeyi kısa keser.
Zamanlayıcı gerektiren kararlar (bekleme penceresi, karadelik, zaman aşımına
uğrayan akışlar) ~2 Hz'lik bir bakım tik'inde çözülür ve canlı kararlar gibi
keşfe geri beslenir.

### Keşif yaşam döngüsü

Keşif **hedef bazındadır**; *hedef*, küçük harfe çevrilmiş SNI sunucu adıdır.
Okunabilir SNI'si olmayan bir `ClientHello` (zaten parçalanmış ya da ECH) asla
değiştirilmez ve asla hedef olmaz.

```
  ┌─────────┐   ilk ClientHello değiştirilmeden geçer
  │  Probe  │   ── Success ──▶ Active (geçiş sorunsuz, yapılacak bir şey yok)
  └────┬────┘
       │ DpiReset / Blackhole
       ▼
  ┌──────────┐  gridi tara; eşzamanlı bağlantılar farklı adayları
  │ Discover │  paralel alır ("uçuşta" olarak izlenir)
  └────┬─────┘
       │ bir aday kendi üst üste 2 Success'ini alır
       ▼
  ┌─────────┐   o Strategy kilitlenir ve bu siteye açılan sonraki
  │ Active  │   tüm bağlantılarda kullanılır
  └────┬────┘
       │ aktif Strategy üst üste 3× başarısız olur
       ▼   (düşürülür — bu hedef için keşif yeniden başlar)
  ┌───────────┐  her aday denendi, hiçbiri çalışmadı
  │ Exhausted │  (grid sonradan büyürse otomatik canlanır)
  └───────────┘
```

- **Paralel tarama.** Aynı engelli siteye aynı anda açılan iki bağlantıya
  *farklı*, denenmemiş adaylar verilir; böylece tarama, uygulama yeniden
  denedikçe hızlanır. Hiç çözülmeyen bir "uçuştaki" aday, 15 sn sonra taramayı
  bloklamayı bırakır. "Üst üste 2 Success" terfi sayacı **aday başına** tutulur;
  paralelde iki farklı adayın birer kez başarması bir terfiye toplanmaz.
- **Yeniden iletim farkındalığı.** Bir akış için strateji üretildikten sonra, o
  akıştaki sonraki `ClientHello` bir yeniden iletimdir ve dokunulmadan iletilir —
  yükseltme (amplification) olmaz.
- **Geçici başarısızlıklar bir kez affedilir.** `DpiReset` (kasıtlı ara-kutu
  sıfırlaması) adayı hemen eler, ama anlık paket kaybı olabilen `Blackhole`, aday
  park edilmeden önce bir kez daha denenir. Bir deneme-sayısı tavanı
  (`grid boyutu × 2`) yine de, affedilen adaylar taramayı sürdürse bile
  `Exhausted`'a ulaşmayı garanti eder.
- **Grid canlanması.** Örneğin 154 stratejilik bir gridi tüketen ve sonradan 166
  stratejilik bir gridle yüklenen bir hedef, yeniden `Discover`'a girer ve
  yalnızca yeni adayları dener — eski `tried` listesi korunur.
- **Tahliye.** Boşta duran `Probe` / geçiş hedefleri 24 saat sonra, herhangi bir
  hedef 7 gün sonra düşürülür ve 4096 hedeflik sabit bir üst sınır en-düşük-değer
  önce uygulanır. Bu, 7/24 çalışan bir sürecin temas edilen her sunucu adı için
  bir kayıt biriktirmesini engeller.

### Ağ bazında hafıza (NetKey)

Öğrenilen durum, ağ başına bir JSON dosyası olarak kalıcılaştırılır. **NetKey**,
`ağ geçidi IPv4 + alt ağ CIDR + birincil DNS soneki` değerinin kısa bir onaltılık
öneke hash'lenmiş halidir. Ağ geçidi adaptörü, `8.8.8.8`'e doğru
`GetBestInterface` ile seçilir; böylece listede yalnızca ilk sırada olan bir
Hamachi / VPN / Radmin sanal adaptörü anahtarı bozmaz.

- Profil, hedef başına şunları kaydeder: faz, `tried` listesi, aday başına
  başarı/deneme sayıları, terfi eden strateji ve sunucunun tahmin edilen başlangıç
  TTL'i.
- **Yalnızca yeniden öğrenmeye değer hedefler yazılır**: devam eden bir
  `Discover` taraması, terfi etmiş stratejisi olan bir `Active` hedef veya bir
  `Exhausted` hedef. Hiç engellenmemiş host'lar (probe başarılı) kalıcılaştırılmaz
  — bir stratejiye ihtiyaçları yoktur ve bir sonraki bağlantıda bedavaya yeniden
  kurulurlar; kaydetmek yalnızca dosyayı şişirir.
- Bir **grid imzası** (her aday kimliği üzerinde FNV-1a) da saklanır. Grid
  derlemeler arasında değiştiyse, eski girdiler yeniden numaralandırılmış
  kimliklere güvenmek yerine zarifçe "yalnızca öğrenilen TTL'i tut"a düşer.
- Yazmalar kısıtlanır (her 30 sn) ve ayrıca temiz kapanışta yapılır.
- Parmak izi okunamazsa anahtar `nonet` olur ve o oturum **yalnızca bellekte**
  tutulur — bilinmeyen bir ağda başarısız bir probe, gerçek bir ağın dosyasını
  asla kirletmez.
- **Bir ağın profili asla silinmez.** Her NetKey'in dosyası yalnızca oluşturulur
  ya da o **aynı ağın** daha yeni durumuyla yerinde üzerine yazılır (atomik
  geçici dosya + rename). Ağ değiştirmek eski ağın dosyasını diske boşaltır ve
  yeni ağınkini yükler — başka hiçbir ağın dosyasına dokunmaz, onu birleştirmez
  ya da silmez. Aylarca ev, ofis ve telefon hotspot'u arasında dolaşın; her ağ
  kendi öğrendiği stratejileri bozulmadan korur.

### Canlı ağ değişimi

Wi-Fi'de dolaştığınızda, bir VPN'i açıp kapattığınızda ya da DHCP yenilediğinizde,
bir Windows rota-değişikliği / adres-değişikliği geri çağrısı bir yeniden kontrol
tetikler. Sonraki bakım tik'inde, 5 sn'lik bir bekleme (debounce) sonrası ve en
fazla 30 sn'de bir, Bosphorus NetKey'i yeniden hesaplar. Değiştiyse:

1. eski ağın öğrenilen durumunu o ağın kendi dosyasına boşaltır,
2. yeni ağ için taze bir oturum kurar (varsa dosyasını yükler),
3. onu atomik olarak yerine geçirir ve
4. eski bağlantı-takip durumunu temizler.

Yeniden başlatma yok, yakalama kesintisi yok.

## Atlatma araç kutusu

Bir `Strategy`, tek bir `ClientHello`'ya uygulanan bir tariftir. Şu parçalardan
kurulur:

**Sahte / desync paketi** — gerçek paketin yanında gönderilen, ara kutunun kabul
edip sunucunun attığı fazladan bir paket:

| Yöntem            | Ne yapar                                                                    |
|-------------------|--------------------------------------------------------------------------|
| `WrongSeq`        | `SEQ`/`ACK`'i geçmişe kaydırılmış sahte (GoodbyeDPI'nin `-10000` / `-66000` değerleri). |
| `WrongChecksum`   | Bilerek bozulmuş TCP sağlama toplamına sahip sahte.                     |
| `TtlLimited`      | Düşük TTL'li sahte; sunucuya varmadan önce süresi dolar.               |
| `SeqPlusTtl`      | `WrongSeq` + düşük TTL.                                                 |
| `ChecksumPlusTtl` | `WrongChecksum` + düşük TTL.                                            |
| `OverlapDisorder` | Ayrı bir sahte yok: gerçek segmentler ters sırayla gönderilir ve ikincisinin önüne `seqovl` kadar çöp bayt eklenir (zapret'in `disorder` + `seqovl`'ı). Yalnızca isteğe bağlı. |

**Parçalama** — TCP yükünü bir veya daha fazla çapa noktasında böl:

- `AbsoluteOffset(n)` — sabit bir bayt konumu.
- `TlsRecordStart` — 5 baytlık TLS kayıt başlığından hemen sonra.
- `SniStart` — SNI sunucu adından hemen önce (`--frag-by-sni`).
- `SniMiddle` — SNI sunucu adının içinde.
- Birden çok çapa → birden çok segment. İsteğe bağlı `reverse`, son segmenti önce
  gönderir.

**Sahte yük** — GoodbyeDPI'nin bire bir 517 baytlık statik `ClientHello`'su, ya
da bir ara kutunun yeniden birleştirme tamponunu sınırının ötesine itmek için
fazladan RFC 7685 dolgusu eklenmiş "agresif" bir varyant.

**TTL politikası** — sabit bir kullanıcı değeri, ya da `SYN`+`ACK` atlama
sayısından türetilen otomatik sezgisel `clamp(sunucuya_atlama − 4, 3, 10)`.

**TLS dolgusu (`tls_pad`)** — parçalamadan *önce* `ClientHello`'ya eklenen bir
RFC 7685 dolgu uzantısı; böylece kayıt, DPI'nin yeniden birleştirmesinin ayırdığı
sabit tamponun ötesine büyür.

**Gönderim sırası** — önce-sahte-sonra-gerçek ya da tersi. **Tekrarlar** — sahteyi
N kez gönder (GoodbyeDPI'nin `--fake-resend`'i).

**Sunucu yığını kapısı.** `OverlapDisorder` sunucuya çöp bayt besler ve yalnızca
*son-geleni-kabul-eden* bir yığına karşı çalışır. Bosphorus, sunucunun başlangıç
TTL'ini `SYN`+`ACK`'ten okur (64 = Linux/unix, 128 = Windows, 255) ve bir Windows /
ilk-geleni-kabul-eden sunucuya asla bir overlap adayı vermez.

## Keşif gridi

Varsayılan grid **166 stratejidir** ve ucuz kazanımların önce gelmesi için kabaca
her birinin ne sıklıkla işe yaradığına göre sıralanır:

| Aile                              | Adet  | Notlar                                          |
|-----------------------------------|-------|-----------------------------------------------|
| Tekli bölme parçalama + sahte     | 142   | 7 çapa × {ileri, ters} × 6 desync türü × {1, 2} tekrar, tekilleştirilmiş. |
| Çok parçalı yerel parçalama       | 12    | 3 seçilmiş kesim deseni × {ileri, ters} × {sahte yok, wrong-seq}. |
| RFC 7685 `tls_pad`                | 6     | 3 çapa × {wrong-seq, wrong-checksum}, 512 baytlık dolgu. |
| "Agresif" sahte                   | 6     | Daha büyük dolgulu sahte × 3 çapa × {wrong-seq, wrong-checksum}. |
| `OverlapDisorder`                 | +8    | **Yalnızca** `--enable-overlap` ile → toplam 174. 4 çapa × 2 `seqovl`. |

`bosphorus --engine --strategy list` derlemenizin tam gridini yazdırır.

## Proje yapısı

Cargo workspace, üç crate:

| Crate               | Rolü                                                                       |
|---------------------|--------------------------------------------------------------------------|
| `bosphorus-core`    | Motor: paket ayrıştırma, bağlantı takibi, strateji modeli, üretici grid, keşif zamanlayıcısı, ağ bazında kalıcılık. **Platform bağımsız** — WinDivert'e veya `windows` crate'ine bağımlılığı yok. Ağla `PacketSource` / `PacketSink` özellikleri (trait) üzerinden konuşur. |
| `bosphorus-divert`  | `windivert-sys` FFI üzerinden WinDivert 2.2 çevresinde ince, tahsissiz (allocation-free) **güvenli bir sarmalayıcı** (`WinDivertOpen`/`Recv`/`Send`/`CalcChecksums`/`SetParam`/`Shutdown`/`Close`, artı filtre derlemesi). |
| `bosphorus-cli`     | `bosphorus` ikili dosyası. WinDivert arka ucunu çekirdek motora bağlar; Windows Hizmeti barındırıcısını, NetKey hesabını, rota-değişikliği izleyicisini, yapılandırılmış günlüklemeyi, Event Log sağlayıcısını ve küçük, elle yazılmış bir EN/TR mesaj kataloğunu ekler. |

## Gereksinimler

- **Windows x64.** Sürücü sarmalayıcısı `#![cfg(windows)]`'tır.
- WinDivert sürücüsünü açan her şey için **Yönetici hakları** (`--engine`,
  `--selftest`, `--passthru`, `--observe`, `service install`). `--check-filters`,
  `--discovery-demo`, `--mem-bench` ve `service status` yükseltme gerektirmez.
- **WinDivert 2.2.2 sürücüsü yüklenebilmelidir.** HVCI / Bellek Bütünlüğü, Smart
  App Control veya bir WDAC politikası, kendi gözlerinde imzasız olan bir sürücüyü
  **boot'ta sessizce** engelleyebilir. `service install`, sürücü yüklemesini
  ön-kontrol eder ve yükleyemezse reddeder (ya da `--force` ile uyarır).
- **Yürütülebilir dosya için sabit bir yol.** WinDivert sürücüyü `.sys` dosyasının
  bulunduğu yoldan kaydeder; `bosphorus.exe`'yi sonradan taşırsanız hizmet (ve
  sürücü) bozulur. `C:\Program Files\Bosphorus\` gibi bir yerde tutun ya da
  `service install --install-dir` kullanın.
- Kaynaktan derlemek için `x86_64-pc-windows-msvc` hedefiyle **Rust** (kararlı,
  ≥ 1.80).

## Kaynaktan derleme

1. **WinDivert 2.2.2 ikili dosyalarını edinin.** `basil00/WinDivert` v2.2.2
   sürümünden resmi `WinDivert-2.2.2-A.zip` dosyasını indirin ve şu yol
   oluşacak şekilde açın:

   ```
   assets/WinDivert-2.2.2-A/x64/WinDivert.dll
   assets/WinDivert-2.2.2-A/x64/WinDivert64.sys
   assets/WinDivert-2.2.2-A/x64/WinDivert.lib
   ```

   `assets/` git tarafından yok sayılır. `.cargo/config.toml`, `WINDIVERT_PATH`'i
   o klasöre işaret ettirir (workspace kökünden çözülen göreli bir yol); Cargo'nuz
   `relative = true`'yu yanlış işleyecek kadar eskiyse oraya mutlak bir yol yazın.

2. **Derleyin.**

   ```powershell
   cargo build --release                 # günlük optimize derleme
   cargo build --profile release-dist    # dağıtılan çıktı: fat LTO, strip'lenmiş
   ```

   `bosphorus-divert`'in derleme betiği `WinDivert.dll` ve `WinDivert64.sys`
   dosyalarını hem `bosphorus.exe`'nin **hem de** test ikili dosyalarının yanına
   yerleştirir; böylece `cargo test` ve düz bir `cargo run` sürücüyü bulur.

3. **Test edin.**

   ```powershell
   cargo test                            # birim + entegrasyon testleri (yükseltme yok)
   ```

   > **Derleme profilleri `panic = "unwind"`'i bilerek korur.** Temiz kapanış
   > yolu (SCM `SERVICE_STOPPED`, son profil boşaltması, bir `Drop` içinde
   > `WinDivertClose`) tümüyle unwind sırasında çalışır. `panic = "abort"`'a
   > geçmeyin.

## Komut satırı kullanımı

```
bosphorus <komut> [seçenekler]
```

| Komut                                     | Yükseltme | Ne yapar                                                                 |
|-------------------------------------------|:---------:|----------------------------------------------------------------------|
| `--engine [--secs N] [--strategy S] [--enable-overlap]` | evet | Motoru çalıştır. `--strategy` yoksa bu, ağ bazında kalıcılık ve canlı ağ-değişimi ile tam **otomatik keşiftir**. `--strategy` ile tek bir sabit strateji zorlar (ağdan bağımsız, kalıcılaştırılmaz). `--secs N` N saniye sonra otomatik durur; yoksa `Ctrl+C`. |
| `--check-filters`                         | hayır     | WinDivert filtre dizgelerini kurar ve `WinDivertHelperCompileFilter`'a karşı sözdizimi kontrolü yapar. |
| `--discovery-demo [--fresh]`              | hayır     | Keşif döngüsünün çalıştığının ve tarama ilerlemesinin süreçler arasında kalıcı olduğunun sürücüsüz kanıtı. `--fresh` önce demo profilini siler. |
| `--mem-bench [N]`                         | hayır     | Motoru `N` sentetik hedefle (varsayılan 2000) sürer ve RAM ayak izini yazdırır. |
| `--observe [--secs N]`                    | evet      | Yalnızca analiz. Tüm portlardaki **tüm** TCP + UDP'yi dinler, hiçbir şeyi değiştirmez ve hedef başına bir profil tablosu yazdırır (SNI / IP, port, protokol, kaba sonuç). Discord masaüstü istemcisi gibi bir uygulamanın gerçekte ne yaptığını incelemek için yapılmıştır. |
| `--passthru [--secs N]`                   | evet      | Her `:443` TCP paketini yakala, günlükle ve **değiştirmeden** yeniden enjekte et — "internet hâlâ çalışıyor" duman testi. |
| `--selftest`                              | evet      | WinDivert doğrulama düzeneği (V1–V4): yeni akış ilk segmentleri, `ClientHello` boyutları, yanlış-sağlama toplamı hayatta kalması, sürücü yüklemesi + sürüm. |
| `--selftest-m7`                           | evet      | Overlap / disorder fizibilite probları (V-A / V-B / V-C). |
| `service <install\|uninstall\|run\|status>` | değişir | Bkz. [Windows Hizmeti olarak çalıştırma](#windows-hizmeti-olarak-çalıştırma). |

**Dil.** `--engine` yolundaki ve hizmet komutlarındaki mesajlar varsayılan olarak
İngilizcedir; Windows arayüz dili Türkçeyse Türkçedir. `--lang en|tr` ya da
`BOSPHORUS_LANG` ortam değişkeni ile geçersiz kılın. Geliştirici `tracing` çıktısı
ve tanılama alt komutları İngilizce kalır.

**Günlük ayrıntısı.** `RUST_LOG` ayarlayın, örn.
`RUST_LOG=bosphorus::discovery=info,bosphorus::strategy=info,bosphorus::conntrack=info`.
`bosphorus::mem=debug` periyodik ayak izi özetini açar.

### `--strategy` dilbilgisi

```
--strategy list                       varsayılan gridi satır satır yazdır
--strategy grid:<i>                    <i> numaralı grid girdisini çalıştır
--strategy overlap:<seqovl>/<anchor>   zorlanmış OverlapDisorder (disorder + seqovl)
--strategy <frag>[/<desync>]           elle bir strateji kur
```

- `<frag>` = tek bir çapa, ya da çok parçalı bölme için virgülle ayrılmış liste,
  ya da `none`. Bir çapa `<u16>` (mutlak konum) | `sni` | `sni-mid` | `tls`.
- `<desync>` = `wrongseq` (varsayılan) | `wrongsum` | `ttl:<u8>` | `none`.
- Herhangi bir biçime `+pad:<n>` ekleyerek `n` baytlık bir RFC 7685 `tls_pad`
  zorlayın.

Örnekler:

```powershell
bosphorus --engine --strategy sni                 # SNI'den hemen önce böl, wrong-seq sahte
bosphorus --engine --strategy tls,sni             # 3'e bölme: kayıt başlığı | gövde | SNI ve sonrası
bosphorus --engine --strategy 2/wrongsum          # konum 2'de böl, bozuk-sağlama sahtesi
bosphorus --engine --strategy sni-mid/ttl:6       # SNI içinde böl, TTL-6 sahte
bosphorus --engine --strategy 2/wrongseq+pad:512  # + 512 baytlık TLS dolgu uzantısı
bosphorus --engine --strategy overlap:16/sni --enable-overlap
bosphorus --engine --strategy grid:0              # ilk grid girdisi neyse
```

## Windows Hizmeti olarak çalıştırma

```powershell
# Kurulum: "Bosphorus" hizmetini oluşturur (LocalSystem, gecikmeli otomatik
# başlangıç, hata sonrası yeniden başlatma) ve başlatır. WinDivert sürücü
# yüklemesini ön-kontrol eder.
bosphorus service install [--lang en|tr] [--enable-overlap]
                          [--profile-dir <yol>] [--install-dir <yol>]
                          [--start auto|demand] [--force]

bosphorus service status         # yükseltme yok; en yeni profil dosyasının yaşını da yazar
bosphorus service uninstall [--purge]   # --purge, %ProgramData%\Bosphorus'u da siler
bosphorus service run            # yalnızca SCM giriş noktası — etkileşimli kullanım için değil
```

- `--install-dir`, `bosphorus.exe`, `WinDivert.dll` ve `WinDivert64.sys`
  dosyalarını sabit bir klasöre kopyalar ve hizmeti kopyadan kaydeder.
- Kurulum programı, **hizmetin ve sürücünün gerçekten geldiğini doğrulamak** için
  bir dizi PowerShell komutu yazdırır (`Get-Service Bosphorus`, CodeIntegrity olay
  günlüğü, HVCI durumu, profil dosyaları). Bunları çalıştırın — boot zamanı bir
  sürücü engeli aksi halde görünmez.
- Hizmet, `--strategy`'siz `--engine` ile aynı otomatik keşif motorunu çalıştırır:
  `%ProgramData%\Bosphorus\profiles` altında ağ bazında kalıcılık, rota-değişikliği
  izleyicisi ve `%ProgramData%\Bosphorus\logs` altında yapılandırılmış dosya
  günlüğü. Yaşam döngüsü olayları ayrıca Windows **Application** olay günlüğüne
  `Bosphorus` sağlayıcı adıyla gider.

## Dosyalar, klasörler ve günlükler

| Yol                                          | Nedir                                                  |
|----------------------------------------------|------------------------------------------------------|
| `assets/WinDivert-2.2.2-A/x64/`              | Derleme sırasında sağladığınız WinDivert çalışma dosyaları. |
| `%LOCALAPPDATA%\Bosphorus\profiles\*.json`   | **Etkileşimli** bir `--engine` çalışması için öğrenilen keşif profilleri — NetKey başına bir tane. |
| `%ProgramData%\Bosphorus\profiles\*.json`    | Aynısı, **hizmet** için (SYSTEM `%LOCALAPPDATA%` kullanamaz). |
| `%ProgramData%\Bosphorus\logs\`              | Döngüsel hizmet günlük dosyaları.                     |

**Depo seçimi.** `--profile-dir DIR` verilirse aynen kullanılır. Aksi hâlde
etkileşimli bir `--engine`, **hizmet kuruluysa ve mevcut ağ için zaten bir
profili varsa** hizmetin `%ProgramData%` deposunu kullanır ("hizmet = otorite"),
böylece iki çalışma modu tek bir ağ-bazlı hafızayı paylaşır; yoksa eskisi gibi
kullanıcıya özel `%LOCALAPPDATA%` deposunu kullanır. Yazma, süreç başına bir
hazırlık dosyası ile atomik son-yazan-kazanır değiştirmedir — hizmet ile uzun bir
etkileşimli `--engine`'i aynı depoya aynı anda koşturmak dosyayı bozmaz ama
birbirlerinin adımsal öğrenmesini ezebilirler (profil bir önbellek, defter değil).
| Windows Application olay günlüğü, `Bosphorus` sağlayıcısı | Hizmet başlat / durdur / açma-hatası / panik kırıntıları. |

Çalışan bir örneği inceleyin:

```powershell
Get-Service Bosphorus
Get-WinEvent -ProviderName Bosphorus
Get-ChildItem "$env:ProgramData\Bosphorus\profiles\*.json" | Select Name, LastWriteTime
```

## Güvenlik ve tasarım kararları

- **İnternet çalışmaya devam etmeli.** `Probe`, ilk `ClientHello`'yu dokunmadan
  gönderir. IP olmayan / TCP olmayan trafik asla incelenmez. Okunabilir SNI'si
  olmayan bir `ClientHello` asla değiştirilmez. `--passthru`, yakalama + yeniden
  enjeksiyonun şeffaf olduğunun sürekli bir kanıtı olarak vardır.
- **`OverlapDisorder` isteğe bağlıdır.** İlk-geleni-kabul-eden bir sunucuya karşı
  handshake'i tıkayabilir; bu yüzden `--enable-overlap` vermedikçe otomatik keşif
  onu asla taramaz — verseniz bile Windows yığınlı sunuculardan uzak tutulur.
- **`panic = "unwind"` yük taşır** (temiz SCM durdurma, son profil boşaltması, bir
  `Drop` içinde `WinDivertClose`). Paket başına döngü `catch_unwind` içine sarılır.
- **Bire bir üçüncü taraf baytları öyle işaretlenir.** WinDivert filtre parçaları
  ve 517 baytlık sahte `ClientHello`, GoodbyeDPI'dan bayt bayt kopyalanır ve
  "düzeltilmemesi" için not düşülür. Tek bilinçli istisna, çağrı anında statik
  sahte artı fazladan RFC 7685 dolgusuyla kurulan "agresif" sahtedir.
- **7/24 çalışmalar için sınırlı bellek.** Hedef tahliyesi, 4096'lık sabit sınır
  ve terminal geçişlerinde `TargetState::compact()`, ayak izini düz tutar;
  `bosphorus::mem` özeti bunu izlemenizi sağlar.

## Sınırlamalar ve kapsam dışı

- **Yalnızca Windows**, x64, yalnızca 443 portunda TLS-üzeri-TCP. Düz HTTP ve
  443 dışı TLS motor tarafından işlenmez.
- **QUIC / HTTP-3.** Bir QUIC-düşürme WinDivert filtresi tanımlı ve sözdizimi
  kontrollüdür (`--check-filters`), ancak özel `DROP` tanıtıcısı çalışan motor
  tarafından henüz açılmadığından QUIC şu an geçirilir. Bir sansürcü SNI'yi QUIC
  üzerinden de engellediğinde, tarayıcı TCP'ye geri dönene kadar o sitelerde hâlâ
  başarısız olabilir.
- **DNS.** `EvasionConfig`'in bir `dns_upstream` alanı var ve filtre kurucu bir
  `udp/53` yan tümcesi ekleyebilir, ancak DNS yönlendirmesi CLI'ye henüz
  bağlanmadı; DNS zehirlenmesi yalnızca gözlemlenebilir, düzeltilmez.
- **IP katmanı parçalama** analiz edilip bilinçli olarak rafa kaldırıldı (karadelik
  riski, Windows'ta doğrulanmadı).
- **Domain fronting / SNI sahteciliği** kapsam dışıdır — yalnızca paket
  manipülasyonunun sağlayamayacağı istemci iş birliği gerektirir.
- **ECH (Şifreli Client Hello).** Açık SNI olmadan keşfi anahtarlayacak bir şey
  yoktur; bu tür handshake'ler doğrudan geçirilir.

## Teşekkürler ve atıf

- ValdikSS tarafından **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** —
  WinDivert filtre parçaları ve statik sahte `ClientHello` bire bir kullanılır;
  sahte-paket desync yöntemleri (`--wrong-seq`, `--wrong-chksum`, `--fake-resend`,
  `--frag-by-sni`, `--reverse-frag`) buradan modellenmiştir.
- bol-van tarafından **[zapret](https://github.com/bol-van/zapret)** — `disorder`
  + `seqovl` overlap tekniği ve otomatik-TTL sezgisel biçimi.
- basil00 tarafından **[WinDivert](https://github.com/basil00/WinDivert)** — paket
  yakalama/enjeksiyon sürücüsü. Kendi lisansı altında ayrıca paketlenir.
- FFI bağlamaları için `windivert-sys` crate'i.

## Lisans

`Cargo.toml`'da bildirildiği üzere, sizin tercihinize göre **MIT VEYA Apache-2.0**
altında çift lisanslıdır. WinDivert kendi şartları altında dağıtılır — bkz.
`assets/WinDivert-2.2.2-A/LICENSE`.
