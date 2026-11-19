# HANDOFF — Bosphorus devralma ve düzeltme işi

**Yazıldı:** 2026-11-14  
**Okuyucu:** bu işe sonradan devam edecek kişi veya ajan. Hiçbir sohbet geçmişi varsayılmamalı — bu dosya tek başına yeterli olacak şekilde yazıldı.  
Aynı makinede devam ediliyorsa `docs/bulgular-2026-11-13.md` ile birlikte oku. Bu dosya tek parça teslim kopyasıdır: bulgu raporunun tam metni sonda EK A olarak eklenmiştir, başka dosyaya ihtiyaç yok.

---

## 1. Ne yapıyoruz

Bosphorus, Windows için bir DPI-atlatma aracı: WinDivert ile paketi yakalar, TLS ClientHello'yu böler/zehirler, strateji keşfi yapar, LocalSystem servisi olarak çalışır. Proje kullanıcının kendi projesi değil — arkadaşından devralıyor. Bu yüzden önce haritalama ve bulgu raporu yapıldı, sonra düzeltmeleri sıfırdan yazma kararı verildi.

**Verilen kararlar (değiştirmeden önce sor):**
- Eski fork commit'leri (`fix/security-code`, 8 commit) kullanılmayacak. Onları yazan model daha zayıftı; düzeltmeler main'in kendi yapısına sıfırdan, daha küçük yazılacak. Fork yalnızca fikir referansı.
- `pr/windows-console-logging` dalı temiz bulundu; taşınabilir.
- Düzeltmeler kategori kategori ayrılacak: güvenlik / yeni özellik / fix / chore / docs. Bir yeni özelliğin güvenlik düzeltmesi aynı dosyaya dokunuyorsa o özelliğin PR'ı altında gider.
- Dal yapısı = A planı: **stacked branches** (kategori önce, dallar sırayla üst üste). Sebep: `service/install.rs` gibi dosyalara birden çok kategori dokunuyor; ayrı PR'lar çakışırdı.

---

## 2. Bugünkü durum (ölçüldü, tahmin değil)

| Kontrol | Sonuç |
|---|---|
| Dal / commit | `main @ f8738b7` (bosphorus-cli v1.0.0, core 0.1.0) |
| `cargo check --workspace` | ✅ hatasız |
| `cargo nextest run --workspace` | ✅ 258/258 |
| `cargo clippy --workspace --all-targets` | ✅ 0 uyarı |
| Toolchain | MSVC 14.44 + Windows SDK 22621, link.exe var |
| `WINDIVERT_PATH` | `.cargo/config.toml` içinde, `assets/WinDivert-2.2.2-A/x64` |

Yani taban sağlam. Üstüne yazılacak.

Yeni (henüz commit edilmemiş) dosyalar: `AGENTS.md`, `docs/bulgular-2026-11-13.md`, `docs/HANDOFF.md` (bu dosya).

**İlk iş:** bunları commit et ve kendi fork'una push et. `origin`'e (Dark-Hunter-TR/Bosphorus) push yetkisi yok. Push edilmezse makine değişince bu iş kaybolur.

---

## 3. Ortam (yeniden kurulması gerekirse)

- `cargo-nextest` 0.9.151 gerekli (`cargo nextest run --workspace`).
- `rust-analyzer-mcp` 0.4.0 + `C:\Users\hp\.config\opencode\opencode.json` içinde MCP kayıtları (rust-analyzer eklendi).
- MCP sunucuları: context7, exa, github, mslearn, playwright, wireshark, rust-analyzer.
- PowerShell'de `.ps1` engelli → `npm.cmd`, `npx.cmd`, `opencode.cmd` kullan.
- `setup.exe modify --wait` kabul etmez (exit 87).

### 3.1 MCP ve skill envanteri

Bunlar repo dışında yaşar — makine değişirse yeniden kurulmalı, git clone getirmez. Bu yüzden ayrıca yedeklenmeli.

**MCP sunucuları** (tanımları `C:\Users\hp\.config\opencode\opencode.json` içinde):

| Sunucu | Bu projede ne için |
|---|---|
| context7 | Rust crate / kütüphane dokümanı |
| exa | Web araması ve sayfa okuma |
| github | Issue/PR/dal işlemleri |
| mslearn | Windows API dokümanı (SCM, ACL, WinDivert tarafı) |
| playwright | Tarayıcı otomasyonu (bu işte gerekmedi) |
| wireshark | pcap analizi — gerçek trafik doğrulaması için asıl araç |
| rust-analyzer | tip hataları, kod aksiyonları, referanslar |

Uyarı: `opencode.json` API anahtarları içerebilir. Buluta atarken bu dosyayı kopyalama, sadece kendi özel yedeğinde tut.

**Skill'ler — bu projede gerçekten kullanılanlar:**

| Grup | Skill'ler | Ne zaman |
|---|---|---|
| Rust | rust-api-design, rust-cli, rust-code-review, rust-concurrency, rust-observability, rust-performance, rust-style-clippy, rust-testing, rust-unsafe-ffi, rust-workspace | Her dal açılışında; unsafe/FFI işinde rust-unsafe-ffi zorunlu |
| Süreç | brainstorming, writing-plans, executing-plans, test-driven-development, systematic-debugging, verification-before-completion, requesting-code-review, receiving-code-review, using-git-worktrees, dispatching-parallel-agents, finishing-a-development-branch | Plan → uygulama → inceleme akışı |
| Üslup | ponytail (full) | Küçük, gereksiz kod yazmayan çıktı |

**Yeniden kurulum:**
- `cargo install cargo-nextest --locked`
- `cargo install rust-analyzer-mcp`
- Superpowers skill'leri npm üzerinden; kurulum yolu `~/.cache/opencode/npm/git-superpowers-*/` altında.

---

## 4. Yazılmış belgeler

- `docs/bulgular-2026-11-13.md` — ana bulgu raporu, Türkçe, her iddia dosya:satır kanıtlı.
  - §0 taban çizgisi, §1 yönetici özeti
  - §2–3: B1–B18 bulgu tablosu ve detayları
  - §4: fork dallarının değerlendirmesi
  - §5: repoda birleştirilmemiş eski 505 satırlık analizle karşılaştırma (`origin/claude/proje-analizi-dpi-karsilastirma-ne7nmg`)
  - §6: repo sahibine sorulacak 8 karar sorusu
  - §7: önerilen sıra
  - §8: G1–G12 — `fix/security-code` değerlendirmesinden çıkan, main'de hâlâ açık güvenlik bulguları. **G1 ve G2 kritik.**

---

## 5. Açık iş — SIRADAKİ ADIM

Token limiti nedeniyle iki derin tarama yarıda kaldı, sonuç yok. Bunlar tekrar çalıştırılmalı; çıktıları §2 tablosunu ve dal sıralamasını değiştirebilir.

Aşağıdaki iki komutu paralel iki subagent'a ver (biri bug, biri güvenlik). İkisi de read-only, dosya:satır zorunlu, mevcut bulguları tekrar etmeyip ötesine geçmeli.

### 5.1 Bug taraması — prompt

DEEP CORRECTNESS/BUG AUDIT of the Rust workspace at <REPO_PATH>
(Windows DPI-bypass: WinDivert capture + TCP/TLS packet surgery + strategy discovery).

STRICT: READ-ONLY. Do not edit, create, delete, checkout or run builds.
Stay inside the repo; never read personal folders outside this repo.
No recursive walks outside the repo.
Every claim needs path:line. If unprovable statically, mark SUSPECTED and say
what would confirm it.

FOCUS: bugs, correctness only. Cover all crates: bosphorus-core (engine,
conntrack, packet parse/build, filter, discovery, scheduler, strategy
generation/transforms, profile persist/isp, netkey, censored), bosphorus-cli
(engine_cmd, service install/runner/uninstall/status, launcher/TUI, netkey,
netwatch, logging, i18n, selftests, observe/passthru/mem_bench), bosphorus-divert
(handle, address, checksum, compile, error).

Hunt for: (1) panics reachable from network/user input — slice indexing, unwrap,
casts, underflow, unreachable!, asserts in release paths; (2) integer/length
bugs — u16/u32 casts in length and checksum fields, overflow, off-by-one in
parsers, endianness, record/handshake/extension length bookkeeping;
(3) conntrack state-machine errors — verdicts that can never fire, double
counting, ordering assumptions, retransmit handling, timeout-vs-event races,
misattributed flows; (4) concurrency — lock scope, TOCTOU between separate lock
acquisitions, Arc/Drop lifetimes, packet-loop vs 500ms-tick races, OnceLock,
deadlock; (5) resource growth/leaks — unbounded maps, retry counters without
backoff, handles, temp files; (6) swallowed errors — .ok(), let _ =,
unwrap_or_default on real errors, partial writes; (7) Windows API misuse — SCM
state transitions, stop/shutdown ordering, DLL path resolution, ACL usage,
registry, UTF-16/ANSI, to_string_lossy on paths; (8) learning-system logic —
promotion/demotion counters, in-flight bookkeeping, eviction, seed ordering,
exhausted revival, ISP pool accounting.

BASELINE — known, do NOT restate; verify reachability then go beyond:
B1 tls_pad panic on 6-8 byte ClientHello (packet/tls.rs:121)
B2 inbound filter only 0x16 vs conntrack 0x17/0x15 (filter/builder.rs:36-43 vs conntrack/events.rs:137-150)
B3 profile temp name per-process not per-thread (profile/persist.rs:99)
B4 flow table no hard cap (conntrack/table.rs:32-35)
B6 no install rollback; StartPending error never reports Stopped (service/install.rs:113, runner.rs:83-91)
B7 preflight loads WinDivert from process dir not --install-dir (service/install.rs:192-196)
B11 `--secs abc` silently ignored (main.rs:162)
B12 selftests always exit 0; no clippy/fmt gate (selftest.rs:45, build.yml)
B13 dead code: IpProximity, RealThenFake, score_delta
B14 ~6 locks + 2 Vec allocs per ClientHello (engine.rs:281-382, table.rs:45-52)
B15 fix_ip_length casts len to u16 (packet/builder.rs:92-99)
B17 NetKey drift orphans learned profiles (netkey.rs:41,99-108)
G5 --quic all misses QUIC v2/draft (filter/templates.rs:22)
G8 dns_upstream captures but never rewrites DNS (filter/builder.rs:68-72)
G9 NetWatch failure swallowed (service/runner.rs:133-137)
G10 stale snapshot overwrites newer (persist.rs:90-105)
G11 sanitize("ISP A")=="sanitize(ISP_A)" shares pool file (profile/isp.rs:92-94)
G12 ISP pool keeps withdrawn strategy evidence (isp.rs:149-158)

OUTPUT: findings table ordered by severity (Critical/High/Medium/Low) with
ID, one-line defect, path:line, trigger, consequence, NEW or KNOWN-Bx/Gx,
confidence. Then 8 worst with the full code path and why the test suite misses
it. Then "Top 5 to fix first". Then "Areas I could not judge statically".
No patches. No files written.

### 5.2 Güvenlik taraması — prompt

DEEP SECURITY AUDIT of the Rust workspace at <REPO_PATH>
(Windows DPI-bypass running as a LocalSystem service with a kernel driver).

STRICT: READ-ONLY. Do not edit, create, delete, checkout or run builds.
Stay inside the repo; never read personal folders. No recursive walks outside.
Every claim needs path:line. Mark SUSPECTED when unprovable and say what check
would confirm it.

THREAT MODEL: A = unprivileged local user wanting SYSTEM or wanting to read
what the victim browses. B = remote party/censor sending crafted TCP/UDP/TLS/
QUIC to crash, exhaust, fingerprint or defeat. C = compromised collaborator
with repo write access (CI, release scripts). D = careless admin typo.
Also: what the tool itself leaks about the user.

Hunt for: (1) privilege and install integrity — service binary/DLL/driver
provenance, directory writability, ownership, symlink/junction/hardlink,
ancestor chain, TOCTOU between validate and copy, --install-dir/--profile-dir
accepting arbitrary paths, DACL setting that destroys existing permissions;
(2) filesystem safety — world-readable/writable profiles and logs, predictable
temp names, %TEMP% fallbacks, path sanitisation, filenames from user input,
delete/purge targets; (3) unsafe/FFI soundness — unsafe impl Send/Sync, raw
pointer lifetimes, from_bytes reinterpretation, alignment/size, Drop closing a
handle still in use, CString from dynamic strings, zeroed memory, layout vs
Windows ABI; (4) input-driven memory safety and DoS — every parser, length
arithmetic, allocation sizes from packet fields, attacker-bounded loops, hash
flooding, unbounded tables, O(n) per packet under a global lock; (5) injection
and script surface — PowerShell/Bash/workflow interpolation, command
construction, UAC arg quoting (ShellExecuteW runas), service ImagePath/argv,
env var trust; (6) information disclosure — hostnames/DNS/IPs in logs, Event
Log, profiles, console, panic messages; permissions on those; readable by
standard users; (7) supply chain and release — pinned vs floating deps,
cargo update in release, lockfile, unsigned/unhashed artifacts, workflow token
scopes, tag/version validation, CI secrets; (8) elevation/UAC flow — what is
elevated, whether attacker strings cross the elevation boundary, hidden-window
error paths, can a non-elevated process trigger a privileged action.

BASELINE — known, do NOT restate; verify then go beyond:
G1 no --install-dir => service at current exe path, only a warning (service/install.rs:159-165,:85,:178-188)
G2 install dir owner never checked
G3 only destination dir trusted, not ancestors
G4 --quic blocked gate needs first byte >=0xC0 while parser accepts 0x80 (filter/templates.rs:38)
G5 --quic all driver filter pins a QUIC version (templates.rs:22, builder.rs:75-79)
G6 release workflow interpolates ${{ inputs.* }} into PowerShell with contents:write (manual-build.yml:42-43,70-76)
G7 panic in packet path aborts the service (engine.rs:525)
G9 NetWatch failure swallowed (service/runner.rs:133-137)
B5 SNI logged at INFO into %ProgramData% with inherited ACLs (engine.rs:775-784, logging.rs:31-71)
B16 unsafe impl Send/Sync + unconditional Drop close (divert/handle.rs:21-22,146-154)
B8 unsigned/unhashed artifacts + cargo update (manual-build.yml:89-91)
B18 QUIC drop only udp/443 (templates.rs:22)

OUTPUT: findings table by severity with ID, one-sentence attack scenario,
path:line, attacker (A/B/C/D), impact, NEW or KNOWN, confidence. Then 8 worst
as step-by-step attack chains with preconditions. Then "what the tool reveals
about the user" (privacy). Then "Top 5 by real-world risk". Then "what I could
not verify without a live Windows machine". No patches. No files written.

---

## 6. Dal planı (onaylandı, 14 dal — tarama sonucu değişebilir)

Sıralı: her dal bir öncekinin üstüne kurulur, çakışma olmaz.

| # | Dal | Kategori | İçerik |
|---|---|---|---|
| 1 | sec/install-target | güvenlik | G1 servis yolu, G2 dizin sahibi, G3 üst zincir |
| 2 | sec/data-dir-acl | güvenlik | B5 profil/log yönetici-only |
| 3 | sec/ci-release | güvenlik | G6 workflow enjeksiyonu, B8 --locked + checksum |
| 4 | feat/quic-policy | özellik | G5 QUIC v2, G4 greased Initial, B18 port kapsamı |
| 5 | feat/dns-redirect | özellik | G8 dns_upstream gerçekten yönlendirsin |
| 6 | fix/tls-pad-panic | fix | B1 |
| 7 | fix/persist-race | fix | B3 + G10 |
| 8 | fix/conntrack-limits | fix | B4 + B14 |
| 9 | fix/inbound-verdicts | fix | B2 (sahibin kararına bağlı) |
| 10 | fix/service-lifecycle | fix | B6 + B7 |
| 11 | fix/learning-stability | fix | G9 + G11 + G12 + B17 |
| 12 | fix/misc | fix | B11 + B15 + B16 |
| 13 | chore/dead-code | chore | B13 + B12 |
| 14 | docs/accuracy | docs | B9 + B10 + eski analiz |

Ayrıca hazır: `pr/windows-console-logging` — temiz.

---

## 7. Tasarım ilkeleri (bunlara uy)

- Küçük yaz. Fork'un install.rs'i 1269 satır; main'inki 289. Aynı güvenlik işi ~80-100 satırla yapılabilir.
- Mevcut deseni kullan. Yeni soyutlama, yeni modül, "ileride lazım olur" kodu yok.
- Her parça testiyle.
- Tek dev commit değil. Her dal kendi içinde derlenir, test geçer.
- Doğrulama olmadan "bitti" deme. `cargo nextest run --workspace` ve `cargo clippy --all-targets` çıktısını gör.

---

## 8. Bilinen tuzaklar (bunları tekrar etme)

- `lock_down` herhangi bir dizinin DACL'ini eziyor — yanlış hedefte geri alınamaz hasar.
- `QUIC_DROP`'tan sürüm sabitini kaldırmak → WireGuard/DTLS/oyun trafiği ölüyor.
- `e0afe32` tek başına → %ProgramFiles%'daki kalıtsal CREATOR OWNER nedeniyle service install çalışmaz.
- Panik sonrası `Ok(())` dönmek → SCM temiz duruş sanıyor, yeniden başlatma tetiklenmiyor.
- Her paket için `data.to_vec()` → sıcak döngüde paket başına heap ayırma.

---

## 9. Repo sahibine sorulacak 8 soru

Tam metin `docs/bulgular-2026-11-13.md` §6'da. Özet:
1. B1 — tls_pad grid'de kalsın mı?
2. B2 — gelen filtrede yalnızca 0x16 bilinçli mi?
3. B5 — log/profil yönetici-only olmalı mı?
4. B8 — release imzalama/checksum planı var mı, cargo update bilinçli mi?
5. Fork dalları — pr/windows-console-logging alınsın mı?
6. Yön — stabilizasyon / yeni yetenek / ürünleştirme?
7. G1/G2 — kurulum yolu zorunlu olsun mu (%ProgramFiles%)?
8. G7 — panik sonrası süreç çıksın mı, sessizce dursun mu?

---

## 10. Nereden devam edilir — sıra

1. Bu dosyayı ve `docs/bulgular-2026-11-13.md`'yi oku.
2. `git status` — üç dosya untracked olmalı; commit edilmişse daha iyi.
3. §5'teki iki taramayı çalıştır (paralel iki subagent).
4. Çıkan yeni bulguları rapora B19+ / G13+ olarak ekle, §2 tablosunu ve §6 dal planını güncelle.
5. `sec/install-target` ile başla (kritik). Her dal: kod + test + nextest + clippy çıktısı.
6. `main`'e doğrudan commit yok — dal aç, test geç, sonra birleştir.

## Ek — bu belgenin sınırları

- Hiçbir şey canlı ağda test edilmedi. Tüm bulgular kod okumasına ve mevcut test paketinin çalıştırılmasına dayanıyor.
- WinDivert sürücüsünün gerçek davranışı yalnızca kodun varsayımları üzerinden değerlendirildi.
- B5'in ACL sonucu ve B17'nin gerçek ağlardaki etkisi ölçülmedi.
- Fork commit'leri derlenmedi/çalıştırılmadı.

> **Not:** EK A (bulgu raporunun tam metni) `docs/bulgular-2026-11-13.md` dosyasında ayrı olarak bulunmaktadır.
