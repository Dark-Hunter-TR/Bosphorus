<#
.SYNOPSIS
  D throughput / per-packet-overhead measurement for Bosphorus.

  1. Baseline (no Bosphorus): TLS-handshake time + bulk-download speed to an
     UNBLOCKED host.
  2. `--passthru` (capture + reinject, zero strategy logic): same measurements.
     baseline - passthru delta = the pure per-packet engine overhead.
  3. `--engine` running: TLS-handshake time to an Active/Promoted target
     (discord.com) - the real bypass path.
  4. GoodbyeDPI (if installed): same target, for comparison. Auto-skipped if
     not found - never prompts to install.
  5. D1 (ip_octets per-packet Vec alloc) / D2 (WinDivert queue params never
     raised): static facts + the passthru throughput symptom. Any fix that
     needs a code change is only REPORTED, not applied.
  6. One summary table.

.NOTES
  Run from an ELEVATED PowerShell at the repo root:
      powershell -ExecutionPolicy Bypass -File .\scripts\measure-throughput.ps1

  No manual interaction - all curl + background processes. Intercepts :443
  traffic on this machine during the ~1 min `--passthru` and `--engine` windows.
  Windows PowerShell 5.1 compatible. No permanent machine changes; if the
  Bosphorus service is running it is stopped for the run and restarted after.
#>

[CmdletBinding()]
param(
    [int]$HandshakeIters   = 20,
    [int]$ThroughputIters  = 8,
    [int]$WarmupCurls      = 3,
    [long]$DownloadBytes   = 10000000,
    [long]$StressBytes     = 50000000,
    [string]$Exe,
    [string]$UnblockedHost = 'speed.cloudflare.com',
    [string]$ThroughputUrl,
    [string]$StressUrl,
    [string]$ActiveHost    = 'discord.com',
    [string]$GdpiArgs      = '-5'
)

$ErrorActionPreference = 'Stop'
$inv = [System.Globalization.CultureInfo]::InvariantCulture
$script:bg = @()
$script:svcWasRunning = $false

trap {
    Write-Host ("`nERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)") -ForegroundColor Red
    foreach ($p in $script:bg) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($script:svcWasRunning) { Start-Service Bosphorus -ErrorAction SilentlyContinue }
    break
}

$scriptDir = $PSScriptRoot
if ((-not $scriptDir) -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ((-not $scriptDir) -or (-not (Test-Path $scriptDir))) { $scriptDir = (Get-Location).Path }
if ((Split-Path -Leaf $scriptDir) -ieq 'scripts') { $repoRoot = Split-Path -Parent $scriptDir } else { $repoRoot = $scriptDir }
if ((-not $repoRoot) -or (-not (Test-Path $repoRoot))) { $repoRoot = $scriptDir }

# --------------------------------------------------------------------------- #
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Exe {
    if ($Exe) { if (Test-Path $Exe) { return (Resolve-Path $Exe).Path } ; Fail "-Exe '$Exe' not found" }
    foreach ($p in @("$repoRoot\target\release\bosphorus.exe", "$repoRoot\target\debug\bosphorus.exe")) {
        if (Test-Path $p) { return $p }
    }
    Fail "bosphorus.exe not found under $repoRoot\target\{release,debug} - run: cargo build --release"
}

function D([string]$s) {
    $v = 0.0
    [void][double]::TryParse($s, [Globalization.NumberStyles]::Float, $inv, [ref]$v)
    return $v
}
function Ms([double]$sec) { return [math]::Round($sec * 1000, 1) }

function Stats([double[]]$v, [double]$scale = 1.0) {
    $g = @($v | Where-Object { $_ -gt 0 } | ForEach-Object { $_ * $scale })
    if ($g.Count -eq 0) { return [pscustomobject]@{ n = 0; median = $null; p90 = $null; min = $null; max = $null } }
    $s = @($g | Sort-Object)
    $n = $s.Count
    $median = if ($n % 2) { $s[[int](($n - 1) / 2)] } else { ($s[$n / 2 - 1] + $s[$n / 2]) / 2 }
    $p90i = [int][math]::Ceiling(0.9 * $n) - 1
    if ($p90i -lt 0) { $p90i = 0 }
    [pscustomobject]@{
        n = $n; median = [math]::Round($median, 2); p90 = [math]::Round($s[$p90i], 2)
        min = [math]::Round($s[0], 2); max = [math]::Round($s[$n - 1], 2)
    }
}

function Handshake([string]$url) {
    $line = & curl.exe -sk -4 -o NUL --connect-timeout 10 --max-time 15 -w '%{time_appconnect}' $url 2>$null
    if (-not $line) { return 0.0 }
    return (D ($line.Trim()))
}

# Discard `n` requests so DNS / TLS-session / route caches are warm before we
# start counting.
function Warmup([string]$url, [int]$n) {
    for ($i = 0; $i -lt $n; $i++) { [void](Handshake $url) ; Start-Sleep -Milliseconds 200 }
}

function HsSeries([string]$url, [int]$iters) {
    Warmup $url $WarmupCurls
    return @(1..$iters | ForEach-Object { Handshake $url ; Start-Sleep -Milliseconds 150 })
}

function Throughput([string]$url, [string[]]$extra = @(), [int]$maxTime = 45) {
    $line = & curl.exe -sk -4 -o NUL --connect-timeout 10 --max-time $maxTime @extra `
        -w '%{speed_download} %{size_download} %{time_total} %{time_appconnect} %{http_code}' $url 2>$null
    $ce = $LASTEXITCODE
    if (-not $line) { return [pscustomobject]@{ bps = 0.0; size = 0; total = 0.0; appconnect = 0.0; code = 0; curlExit = $ce } }
    $p = ($line.Trim() -split '\s+')
    [pscustomobject]@{
        bps = (D $p[0]); size = [long](D $p[1]); total = (D $p[2]); appconnect = (D $p[3])
        code = [int](D $p[4]); curlExit = $ce
    }
}

# Unblocked throughput sources, tried in order until one responds. 'cf' sizes the
# download via ?bytes=N; 'range' sizes a fixed file via an HTTP Range header.
function Tp-Candidates {
    if ($ThroughputUrl) { return @(@{ kind = 'fixed'; url = $ThroughputUrl }) }
    @(
        @{ kind = 'cf';    url = "https://$UnblockedHost/__down?bytes={0}" }
        @{ kind = 'range'; url = 'https://proof.ovh.net/files/100Mb.dat' }
        @{ kind = 'range'; url = 'https://cachefly.cachefly.net/100mb.test' }
        @{ kind = 'range'; url = 'https://ipv4.download.thinkbroadband.com/1GB.zip' }
    )
}
function Probe-Cand($c) {
    $u = if ($c.kind -eq 'cf') { $c.url -f 300000 } else { $c.url }
    $x = if ($c.kind -eq 'range') { @('-r', '0-299999') } else { @() }
    Throughput $u $x
}
function Tp-Request([long]$bytes) {
    switch ($script:tpKind) {
        'cf'    { @{ url = ($script:tpBase -f $bytes); extra = @() } }
        'range' { @{ url = $script:tpBase; extra = @('-r', "0-$([long]$bytes - 1)") } }
        default { @{ url = $script:tpBase; extra = @() } }
    }
}

function Start-Bg([string]$exe, [string[]]$argList, [string]$tag, [string]$outDir) {
    $o = Join-Path $outDir "$tag.out.log"
    $e = Join-Path $outDir "$tag.err.log"
    $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -NoNewWindow `
        -RedirectStandardOutput $o -RedirectStandardError $e
    $script:bg += $p
    return $p
}
function Stop-Bg($p) {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 600
}

function Find-Gdpi {
    $c = (Get-Command goodbyedpi.exe -ErrorAction SilentlyContinue)
    if ($c) { return $c.Source }
    $roots = @(
        "$env:ProgramFiles\GoodbyeDPI", "${env:ProgramFiles(x86)}\GoodbyeDPI",
        'C:\GoodbyeDPI', 'C:\Tools\GoodbyeDPI', 'C:\Program Files\goodbyedpi',
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop"
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $hit = Get-ChildItem -Path $r -Filter goodbyedpi.exe -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

# --------------------------------------------------------------------------- #
if (-not (Test-Admin)) { Fail 'run from an ELEVATED (Administrator) PowerShell' }
$exe = Resolve-Exe
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Fail 'curl.exe not on PATH' }

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot "measure-out\throughput-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host ""
Write-Host "Bosphorus throughput measurement" -ForegroundColor Cyan
Write-Host "  exe            : $exe"
Write-Host "  unblocked host : $UnblockedHost"
Write-Host ("  throughput url : {0}" -f $(if ($ThroughputUrl) { $ThroughputUrl } else { '(auto-select below)' }))
Write-Host "  active target  : $ActiveHost"
Write-Host "  output         : $outDir"
Write-Host ""

# stop the service for the run (restored in the trap / at the end)
$svc = Get-Service -Name Bosphorus -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "Bosphorus service is Running - stopping it for the measurement (will restart after)." -ForegroundColor Yellow
    Stop-Service Bosphorus -Force -ErrorAction SilentlyContinue
    $script:svcWasRunning = $true
    Start-Sleep -Seconds 2
}

# pick an unblocked throughput source (one flaky host must not kill the run)
Write-Host "  probing unblocked throughput sources ..."
$chosen = $null
$probe = $null
foreach ($c in (Tp-Candidates)) {
    $tag = if ($c.kind -eq 'cf') { $c.url -f '<bytes>' } else { $c.url }
    $r = Probe-Cand $c
    if (-not ($r.code -ge 200 -and $r.code -lt 400 -and $r.size -ge 200000)) {
        Start-Sleep -Milliseconds 800
        $r = Probe-Cand $c
    }
    if ($r.code -ge 200 -and $r.code -lt 400 -and $r.size -ge 200000) {
        Write-Host ("    OK   {0}  ({1} KB probe, {2} MB/s)" -f $tag, [int]($r.size / 1KB), [math]::Round($r.bps / 1MB, 2)) -ForegroundColor Green
        $chosen = $c; $probe = $r; break
    }
    Write-Host ("    fail {0}  (http={1} curlExit={2} size={3})" -f $tag, $r.code, $r.curlExit, $r.size) -ForegroundColor DarkYellow
}
if (-not $chosen) {
    Write-Host ""
    Write-Host "  no unblocked HTTPS throughput source reachable from this network right now." -ForegroundColor Red
    Write-Host "  curl exit: 6=DNS  7=TCP-connect  28=timeout  35=TLS-handshake  56=recv-error  (0 w/ empty body = reset mid-handshake)." -ForegroundColor Red
    Write-Host "  Most likely the line itself is degraded (any throughput number now would be noise)," -ForegroundColor Red
    Write-Host "  or every one of these hosts is being disrupted. Re-run on a healthy connection, or pass" -ForegroundColor Red
    Write-Host "  -ThroughputUrl <a large HTTPS file you can reach> to override." -ForegroundColor Red
    Fail "no reachable unblocked throughput url"
}
$script:tpKind = $chosen.kind
$script:tpBase = $chosen.url
$ThroughputUrl = if ($chosen.kind -eq 'cf') { $chosen.url -f $DownloadBytes } else { $chosen.url }
$StressUrl     = if ($chosen.kind -eq 'cf') { $chosen.url -f $StressBytes }   else { $chosen.url }
# the unblocked *handshake* host follows whatever throughput source we landed on
try { $UnblockedHost = ([uri]$ThroughputUrl).Host } catch { }
Write-Host ("  using: {0}  (kind={1}, handshake host {2})`n" -f $script:tpBase, $script:tpKind, $UnblockedHost)

# generous ceiling for the background lifetime; Stop-Bg force-kills it as soon as
# the measurements finish, so on a healthy line the process is gone in ~40 s and
# a big value here costs nothing. It only needs to exceed the worst-case wall
# time (a degraded line hitting the per-curl --max-time caps).
$life = [int]($HandshakeIters * 3 + $ThroughputIters * 50 + 200)

# --------------------------------------------------------------------------- #
Write-Host "[1/4] baseline (no Bosphorus) ..." -ForegroundColor Green
$b_hs = HsSeries "https://$UnblockedHost/" $HandshakeIters
$b_tp_raw = @(1..$ThroughputIters | ForEach-Object { $t = Tp-Request $DownloadBytes; [math]::Round((Throughput $t.url $t.extra).bps / 1MB, 2) })
$b_stress = & { $t = Tp-Request $StressBytes; Throughput $t.url $t.extra 120 }
$b_dc = @(1..5 | ForEach-Object { Handshake "https://$ActiveHost/" })
$b_hs_s = Stats $b_hs 1000.0                 # ms
$b_tp_s = Stats $b_tp_raw 1.0                 # MB/s (already scaled)
$b_dc_s = Stats $b_dc 1000.0
Write-Host ("      unblocked handshake median={0} ms p90={1} ms min={2}" -f $b_hs_s.median, $b_hs_s.p90, $b_hs_s.min)
Write-Host ("      unblocked download  median={0} MB/s  values: {1}" -f $b_tp_s.median, ($b_tp_raw -join ' '))
Write-Host ("      stress {0} MB   -> {1} MB/s ({2}% complete)" -f ([int]($StressBytes/1MB)), [math]::Round($b_stress.bps/1MB,2), [math]::Round(100.0*$b_stress.size/$StressBytes,0))
Write-Host ("      {0} raw handshake  ok={1}/5 (0 ok => raw-blocked, expected)" -f $ActiveHost, $b_dc_s.n)

# --------------------------------------------------------------------------- #
Write-Host "[2/4] --passthru (capture + reinject, no strategy) ..." -ForegroundColor Green
$p = Start-Bg $exe @('--passthru', '--secs', "$life") 'passthru' $outDir
Start-Sleep -Seconds 3
$pt_hs = HsSeries "https://$UnblockedHost/" $HandshakeIters
$pt_tp_raw = @(1..$ThroughputIters | ForEach-Object { $t = Tp-Request $DownloadBytes; [math]::Round((Throughput $t.url $t.extra).bps / 1MB, 2) })
$pt_stress = & { $t = Tp-Request $StressBytes; Throughput $t.url $t.extra 120 }
Stop-Bg $p
$pt_hs_s = Stats $pt_hs 1000.0
$pt_tp_s = Stats $pt_tp_raw 1.0
$ptOut = if (Test-Path (Join-Path $outDir 'passthru.out.log')) { Get-Content (Join-Path $outDir 'passthru.out.log') } else { @() }
$ptPkts = ($ptOut | Select-String -Pattern 'paket \(' | Select-Object -Last 1)
$ptDone = ($ptOut | Select-String -Pattern 'passthru bitti' | Select-Object -Last 1)
Write-Host ("      unblocked handshake median={0} ms p90={1} ms min={2}" -f $pt_hs_s.median, $pt_hs_s.p90, $pt_hs_s.min)
Write-Host ("      unblocked download  median={0} MB/s  values: {1}" -f $pt_tp_s.median, ($pt_tp_raw -join ' '))
Write-Host ("      stress {0} MB   -> {1} MB/s ({2}% complete)" -f ([int]($StressBytes/1MB)), [math]::Round($pt_stress.bps/1MB,2), [math]::Round(100.0*$pt_stress.size/$StressBytes,0))
if ($ptDone) { Write-Host ("      {0}" -f $ptDone.Line.Trim()) }

# --------------------------------------------------------------------------- #
Write-Host "[3/4] --engine (Active target: $ActiveHost) ..." -ForegroundColor Green

# discord.com's state in the current profile, so we know whether step 3
# measures the bypass path or just passthrough.
$dcState = 'unknown'
$profFile = @(
    (Join-Path $env:LOCALAPPDATA 'Bosphorus\profiles'),
    (Join-Path $env:ProgramData  'Bosphorus\profiles')
) | Where-Object { Test-Path $_ } |
  ForEach-Object { Get-ChildItem $_ -Filter *.json -File -ErrorAction SilentlyContinue } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($profFile) {
    try {
        $pj = Get-Content -Raw $profFile.FullName | ConvertFrom-Json
        $dt = @($pj.targets | Where-Object { $_.key -eq $ActiveHost }) | Select-Object -First 1
        if ($dt) {
            $act = if ($null -ne $dt.active) { 'Active+strategy' } else { 'passthrough/none' }
            $dcState = "phase=$($dt.phase) active=$act  (profile $($profFile.Name), $($profFile.LastWriteTime))"
        } else { $dcState = "not in profile $($profFile.Name)" }
    } catch { $dcState = "profile parse failed: $_" }
}
Write-Host "      $ActiveHost profile state: $dcState"

$env:RUST_LOG = 'bosphorus::strategy=debug,bosphorus::discovery=debug,bosphorus::conntrack=info'
$p = Start-Bg $exe @('--engine', '--secs', "$life") 'engine' $outDir
Start-Sleep -Seconds 4
$en_dc = HsSeries "https://$ActiveHost/" $HandshakeIters
$en_ub = HsSeries "https://$UnblockedHost/" $HandshakeIters
Stop-Bg $p
$env:RUST_LOG = $null
$en_dc_s = Stats $en_dc 1000.0
$en_ub_s = Stats $en_ub 1000.0
$enErr = if (Test-Path (Join-Path $outDir 'engine.err.log')) { Get-Content (Join-Path $outDir 'engine.err.log') } else { @() }
$enOut = if (Test-Path (Join-Path $outDir 'engine.out.log')) { Get-Content (Join-Path $outDir 'engine.out.log') } else { @() }
# tracing_subscriber::fmt() writes to STDOUT, so the strategy/conntrack lines land
# in engine.out.log - scan both streams so a stdout/stderr change can't blind us.
$enLog = @($enOut) + @($enErr)
$reAH = [regex]::Escape($ActiveHost)
$enApplied  = @($enLog | Select-String -Pattern 'applied strategy to ClientHello' | Where-Object { $_.Line -match $reAH })
$enPassthru = @($enLog | Select-String -Pattern 'passthrough \(control' | Where-Object { $_.Line -match $reAH })
$enDcClass  = @($enLog | Select-String -Pattern 'flow classified' | Where-Object { $_.Line -match $reAH })
$enSummary  = @()
$si = ($enOut | Select-String -Pattern 'discovery summary|keşif özeti' | Select-Object -First 1)
if ($si) { $enSummary = $enOut[($si.LineNumber - 1)..([math]::Min($enOut.Count - 1, $si.LineNumber + 40))] }
Write-Host ("      {0} handshake  median={1} ms p90={2} ms min={3}  ok={4}/{5}" -f $ActiveHost, $en_dc_s.median, $en_dc_s.p90, $en_dc_s.min, $en_dc_s.n, $HandshakeIters)
Write-Host ("      unblocked handshake median={0} ms p90={1} ms min={2}" -f $en_ub_s.median, $en_ub_s.p90, $en_ub_s.min)
Write-Host ("      {0}: strategy applied {1}x | passthrough-control {2}x | flow-classified {3}x" -f $ActiveHost, $enApplied.Count, $enPassthru.Count, $enDcClass.Count)

# --------------------------------------------------------------------------- #
Write-Host "[4/4] GoodbyeDPI comparison ..." -ForegroundColor Green
$gdpi = Find-Gdpi
$gd_dc_s = $null
$gdpiNote = ''
if (-not $gdpi) {
    $gdpiNote = 'GoodbyeDPI not found on this system - step skipped (no install attempted).'
    Write-Host "      $gdpiNote" -ForegroundColor Yellow
} else {
    Write-Host "      found: $gdpi   args: $GdpiArgs"
    $ga = @($GdpiArgs -split '\s+' | Where-Object { $_ })
    $gp = Start-Bg $gdpi $ga 'gdpi' $outDir
    Start-Sleep -Seconds 4
    if ($gp.HasExited) {
        $ge = if (Test-Path (Join-Path $outDir 'gdpi.err.log')) { (Get-Content -Raw (Join-Path $outDir 'gdpi.err.log')) } else { '' }
        $go = if (Test-Path (Join-Path $outDir 'gdpi.out.log')) { (Get-Content -Raw (Join-Path $outDir 'gdpi.out.log')) } else { '' }
        $gdpiNote = "GoodbyeDPI exited at once (code $($gp.ExitCode)) - a bare goodbyedpi.exe with no WinDivert.dll/WinDivert64.sys beside it will not run; use the full release zip (its x86_64\ folder). out=[$(($go).Trim())] err=[$(($ge).Trim())]"
        Write-Host "      $gdpiNote" -ForegroundColor Yellow
        $gd_dc_s = $null
    } else {
        $gd_dc = @(1..$HandshakeIters | ForEach-Object { Handshake "https://$ActiveHost/" })
        Stop-Bg $gp
        $gd_dc_s = Stats $gd_dc 1000.0
        $gdpiNote = "GoodbyeDPI $GdpiArgs"
        Write-Host ("      {0} handshake  median={1} ms p90={2} ms  ok={3}/{4}" -f $ActiveHost, $gd_dc_s.median, $gd_dc_s.p90, $gd_dc_s.n, $HandshakeIters)
    }
}

# restart the service if we stopped it
if ($script:svcWasRunning) {
    Write-Host "`nrestarting the Bosphorus service ..." -ForegroundColor Yellow
    Start-Service Bosphorus -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------------------- #
#  D1 / D2 analysis
# --------------------------------------------------------------------------- #
$tpBaseline = $b_tp_s.median
$tpPassthru = $pt_tp_s.median
$tpRatio = if ($tpBaseline -and $tpBaseline -gt 0) { [math]::Round(100.0 * $tpPassthru / $tpBaseline, 1) } else { $null }
$hsOverhead = if ($null -ne $b_hs_s.median -and $null -ne $pt_hs_s.median) { [math]::Round($pt_hs_s.median - $b_hs_s.median, 2) } else { $null }

# --------------------------------------------------------------------------- #
$S = New-Object System.Collections.Generic.List[string]
$S.Add('================ MEASURE-THROUGHPUT SUMMARY (paste this whole block back) ================')
$S.Add("timestamp : $stamp")
$S.Add("exe       : $exe")
$S.Add("outdir    : $outDir")
$S.Add("unblocked : $UnblockedHost   throughput: $ThroughputUrl")
$S.Add("active    : $ActiveHost   handshake iters: $HandshakeIters   throughput iters: $ThroughputIters   dl bytes: $DownloadBytes")
if ($script:svcWasRunning) { $S.Add('note: Bosphorus service was stopped for the run and restarted after.') }
$S.Add('')
$S.Add('--- handshake time_appconnect (ms) ---')
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f 'scenario', 'median', 'p90', 'min', 'max', 'n'))
$S.Add('  ' + ('-' * 82))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "baseline / $UnblockedHost", $b_hs_s.median, $b_hs_s.p90, $b_hs_s.min, $b_hs_s.max, $b_hs_s.n))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "--passthru / $UnblockedHost", $pt_hs_s.median, $pt_hs_s.p90, $pt_hs_s.min, $pt_hs_s.max, $pt_hs_s.n))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "--engine / $UnblockedHost", $en_ub_s.median, $en_ub_s.p90, $en_ub_s.min, $en_ub_s.max, $en_ub_s.n))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "baseline / $ActiveHost (raw)", $b_dc_s.median, $b_dc_s.p90, $b_dc_s.min, $b_dc_s.max, $b_dc_s.n))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "--engine / $ActiveHost (bypass)", $en_dc_s.median, $en_dc_s.p90, $en_dc_s.min, $en_dc_s.max, $en_dc_s.n))
if ($gd_dc_s) {
    $S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f "GoodbyeDPI / $ActiveHost", $gd_dc_s.median, $gd_dc_s.p90, $gd_dc_s.min, $gd_dc_s.max, $gd_dc_s.n))
} else {
    $S.Add("  GoodbyeDPI / $ActiveHost                  --  $gdpiNote")
}
$S.Add('')
$S.Add("--- $ActiveHost profile state at step 3 ---")
$S.Add("  $dcState")
$S.Add("  step 3 log: strategy applied $($enApplied.Count)x | passthrough-control $($enPassthru.Count)x | flow-classified $($enDcClass.Count)x")
if ($en_dc_s.n -gt 0 -and $enApplied.Count -eq 0) {
    $S.Add('  !! step 3 measured PASSTHROUGH, not the bypass strategy (0 applications). The')
    $S.Add('     --engine / ActiveHost row above is NOT a bypass-latency number this run.')
} elseif ($enApplied.Count -gt 0) {
    $S.Add("  OK step 3 exercised the real bypass strategy ($($enApplied.Count) applications to $ActiveHost).")
}
foreach ($l in ($enDcClass | Select-Object -First 8)) { $S.Add("    $($l.Line.Trim())") }
if ($enSummary.Count -gt 0) {
    $S.Add('  engine discovery summary on exit:')
    foreach ($l in $enSummary) { if ($l -match [regex]::Escape('discord') -or $l -match 'summary|özeti') { $S.Add("    $l") } }
}
$S.Add('')
$S.Add('--- bulk download speed (MB/s) ---')
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f 'scenario', 'median', 'p90', 'min', 'max', 'n'))
$S.Add('  ' + ('-' * 82))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f 'baseline', $b_tp_s.median, $b_tp_s.p90, $b_tp_s.min, $b_tp_s.max, $b_tp_s.n))
$S.Add(("  {0,-40} {1,8} {2,8} {3,8} {4,8} {5,5}" -f '--passthru', $pt_tp_s.median, $pt_tp_s.p90, $pt_tp_s.min, $pt_tp_s.max, $pt_tp_s.n))
$S.Add("  baseline  raw values : $($b_tp_raw -join ' ')")
$S.Add("  --passthru raw values: $($pt_tp_raw -join ' ')")
$S.Add(("  stress ({0} MB single download):  baseline {1} MB/s ({2}%)  |  --passthru {3} MB/s ({4}%)" -f `
    ([int]($StressBytes/1MB)), [math]::Round($b_stress.bps/1MB,2), [math]::Round(100.0*$b_stress.size/$StressBytes,0),
    [math]::Round($pt_stress.bps/1MB,2), [math]::Round(100.0*$pt_stress.size/$StressBytes,0)))
$S.Add('')
$S.Add('--- per-packet engine overhead (baseline vs --passthru) ---')
$S.Add("  handshake best-case : baseline min $($b_hs_s.min) ms | --passthru min $($pt_hs_s.min) ms | --engine min $($en_ub_s.min) ms")
$S.Add("     (min is warm-vs-warm; the delta here is the true per-packet handshake cost)")
$S.Add("  handshake median    : $hsOverhead ms  (--passthru - baseline; can be noisy if the line drifted)")
$S.Add("  download speed      : --passthru is $tpRatio % of baseline (8-sample median)")
$sr = if ($b_stress.bps -gt 0) { [math]::Round(100.0 * $pt_stress.bps / $b_stress.bps, 1) } else { $null }
$S.Add("  stress download     : --passthru is $sr % of baseline ($([int]($StressBytes/1MB)) MB single download - the queue-pressure test)")
if ($ptPkts) { $S.Add("  passthru counters   : $($ptPkts.Line.Trim())") }
$S.Add('')
$S.Add('--- D1 / D2 ---')
$S.Add('  D1 (conntrack/table.rs ip_octets(): Vec<u8> heap alloc per shard() call, >=2 per packet):')
$S.Add('     code fact, confirmed by inspection. Not externally isolable - folded into the')
$S.Add('     baseline vs --passthru delta above alongside parse + shard-lock + 80-byte meta copy')
$S.Add('     + one recv + one send syscall. A profiler or a micro-benchmark is needed to')
$S.Add('     attribute the delta to D1 specifically.')
$S.Add('  D2 (WinDivert queue params never raised from the driver defaults):')
$S.Add('     code fact - run_engine() / passthru::run() open the handle and never call')
$S.Add('     set_param(). WinDivert 2.2 defaults: QueueLength 4096, QueueTime 2000 ms,')
$S.Add('     QueueSize 4 MB. GoodbyeDPI raises QueueLength to 16384 (and QueueTime to 8000).')
$S.Add('     Symptom here: the --passthru download-speed ratio above. A ratio well under 100%')
$S.Add('     that gets WORSE with a bigger -DownloadBytes points at queue drops.')
$S.Add('  OPTIONAL EXPERIMENT (report only - NOT applied):')
$S.Add('     add h.set_param(Param::QueueLength, 16384) + h.set_param(Param::QueueTime, 8000)')
$S.Add('     right after WinDivertHandle::open in engine_cmd.rs / passthru.rs (~4 lines),')
$S.Add('     rebuild, re-run this script, compare the --passthru download ratio.')
$S.Add('')
$S.Add('--- interpretation hint ---')
$S.Add('  handshake overhead ~0 ms AND download ratio >~95%  -> per-packet path is fine at this load; "kat kat yavas" is elsewhere')
$S.Add('  download ratio <~85% (worse with bigger downloads) -> D2 queue params are the likely cause; run the optional experiment')
$S.Add('  --engine/ActiveHost median >> --engine/unblocked    -> the bypass strategy itself adds handshake latency (separate from D1/D2)')
$S.Add('  GoodbyeDPI median << --engine/ActiveHost            -> Bosphorus bypass path is slower than GoodbyeDPI for an equivalent target')
$S.Add('===================================================================================')

$txt = ($S -join "`r`n")
$txt | Set-Content -Path (Join-Path $outDir 'SUMMARY.txt') -Encoding utf8
Write-Host ""
Write-Host $txt
Write-Host ""
Write-Host "saved: $(Join-Path $outDir 'SUMMARY.txt')" -ForegroundColor Green
