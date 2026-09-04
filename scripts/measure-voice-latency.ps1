<#
.SYNOPSIS
  Why does joining a Discord voice channel take "sometimes instant, sometimes
  5 s+"? Measures it two ways.

  PHASE 1 (fully automatic, repeatable):
    curl a TLS handshake to latency.discord.media (+ any live c-*.discord.media
    harvested from recent logs) on 443 and every Cloudflare HTTPS-alt port
    (2053/2083/2087/2096/8443), N times each, with --engine OFF (baseline) and
    ON (bypass). Records time_appconnect, HTTP code, and curl exit
    (35 = TLS reset by DPI, 28 = timeout, 0 = ok). -Repeat loops the whole
    battery so an intermittent reset is caught. This isolates the DPI behaviour
    on the voice-SIGNALLING path and whether Phase 2 (a)+(b) fixes it.

  PHASE 2 (-GuidedJoins N, semi-automatic):
    --engine runs with discovery=debug; you join/leave a voice channel N times
    on cue. Per join the script reports every *.discord.media handshake attempt,
    how many were DpiReset, the wall-clock span, and whether "probe skipped" /
    "applied strategy" fired. A fast join = 1 attempt, Success, <1 s; a slow one
    = 2-3 attempts, some resets, 5-15 s.

  Prints ONE summary block. Paste it back.

.NOTES
  ELEVATED PowerShell, repo root:
      powershell -ExecutionPolicy Bypass -File .\scripts\measure-voice-latency.ps1
      ... -Repeat 20                 # unattended: catch the intermittent reset
      ... -GuidedJoins 6             # also do the guided join/leave loop
      ... -NoEngine                  # Phase 1 baseline only (no elevation, no bypass)
      ... -ProfileDir <path>         # engine --profile-dir (default: auto-detect the
                                     # service's %ProgramData%\Bosphorus\profiles store)

  Windows PowerShell 5.1. Stops/restarts the Bosphorus service for the run.
#>

[CmdletBinding()]
param(
    [int]$Iters        = 12,
    [int]$Repeat       = 1,
    [int]$GuidedJoins  = 0,
    [int[]]$Ports      = @(443, 2053, 2083, 2087, 2096, 8443),
    [string[]]$Hosts,
    [string]$Exe,
    [string]$ProfileDir,          # engine --profile-dir; default: auto-detect the
                                  # service's %ProgramData% store if it has profiles
    [switch]$NoEngine,
    [switch]$NoBaseline
)

$ErrorActionPreference = 'Stop'
$inv = [Globalization.CultureInfo]::InvariantCulture
$script:bg = @()
$script:svcWasRunning = $false

trap {
    Write-Host ("`nERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)") -ForegroundColor Red
    foreach ($p in $script:bg) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($script:svcWasRunning) { Start-Service Bosphorus -ErrorAction SilentlyContinue }
    break
}

$scriptDir = $PSScriptRoot
if ((-not $scriptDir) -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ((-not $scriptDir) -or (-not (Test-Path $scriptDir))) { $scriptDir = (Get-Location).Path }
if ((Split-Path -Leaf $scriptDir) -ieq 'scripts') { $repoRoot = Split-Path -Parent $scriptDir } else { $repoRoot = $scriptDir }

function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Resolve-Exe {
    if ($Exe) { if (Test-Path $Exe) { return (Resolve-Path $Exe).Path } ; Fail "-Exe '$Exe' not found" }
    foreach ($p in @("$repoRoot\target\release\bosphorus.exe", "$repoRoot\target\debug\bosphorus.exe")) { if (Test-Path $p) { return $p } }
    Fail "bosphorus.exe not found - cargo build --release"
}
function D([string]$s) { $v = 0.0; [void][double]::TryParse($s, [Globalization.NumberStyles]::Float, $inv, [ref]$v); $v }
function Strip-Ansi([string]$s) { [regex]::Replace($s, "\x1b?\[[0-9;]*m", "") }

function Stats([double[]]$v) {
    $g = @($v | Where-Object { $_ -gt 0 } | Sort-Object)
    if ($g.Count -eq 0) { return [pscustomobject]@{ n = 0; median = 0; p90 = 0; min = 0; max = 0 } }
    $n = $g.Count
    $med = if ($n % 2) { $g[[int](($n - 1) / 2)] } else { ($g[$n / 2 - 1] + $g[$n / 2]) / 2 }
    $p90 = $g[[math]::Max(0, [int][math]::Ceiling(0.9 * $n) - 1)]
    [pscustomobject]@{ n = $n; median = [math]::Round($med, 1); p90 = [math]::Round($p90, 1); min = [math]::Round($g[0], 1); max = [math]::Round($g[$n - 1], 1) }
}

# One TLS handshake. We only care whether the TLS handshake COMPLETED and how
# long it took - `time_appconnect > 0` means the ServerHello came back even if
# the later HTTP body hangs (latency.discord.media / RTC hosts don't serve a
# normal response). `time_appconnect == 0` + curl exit 35/56/52 = DPI reset
# mid-handshake; + exit 28 = the connection stalled before TLS finished.
function Handshake([string]$hostname, [int]$port) {
    $url = "https://{0}:{1}/" -f $hostname, $port
    $line = & curl.exe -sk -4 -o NUL --connect-timeout 5 --max-time 8 `
        -w '%{time_appconnect} %{http_code}' $url 2>$null
    $ce = $LASTEXITCODE
    $p = ($line.Trim() -split '\s+')
    $ms = [math]::Round((D $p[0]) * 1000, 1)
    $verdict =
        if ($ms -gt 0) { 'ok' }
        elseif ($ce -in 35, 56, 52) { 'reset' }
        elseif ($ce -eq 28) { 'timeout' }
        else { 'other' }
    [pscustomobject]@{ ms = $ms; code = [int](D $p[1]); exit = $ce; verdict = $verdict }
}

function Start-Bg([string]$exe, [string[]]$a, [string]$tag, [string]$dir) {
    $o = Join-Path $dir "$tag.out.log"; $e = Join-Path $dir "$tag.err.log"
    $p = Start-Process -FilePath $exe -ArgumentList $a -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
    $script:bg += $p; $p
}
function Stop-Bg($p) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }; Start-Sleep -Milliseconds 700 }

function Harvest-MediaHosts {
    $set = [ordered]@{ 'latency.discord.media' = $true }
    $rx = 'c-[a-z0-9]+(?:-[a-z0-9]+)*\.discord\.media'
    $logs = Get-ChildItem (Join-Path $repoRoot 'measure-out') -Recurse -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 6
    foreach ($f in $logs) {
        $txt = Get-Content -Raw $f.FullName -ErrorAction SilentlyContinue
        if (-not $txt) { continue }   # empty log file -> [regex]::Matches($null) throws
        foreach ($m in [regex]::Matches($txt, $rx)) { $set[$m.Value] = $true }
    }
    @($set.Keys) | Select-Object -First 4
}

# Drop harvested hosts that no longer resolve / connect (RTC hosts are
# per-session ephemeral, so a name from an old log usually times out). One fast
# probe on :443; keep the host if TCP+TLS got anywhere at all (exit 0/35/52/56),
# drop it on could-not-resolve / could-not-connect / timeout (6/7/28).
function Filter-LiveHosts([string[]]$hosts) {
    $live = @()
    foreach ($h in $hosts) {
        if ($h -eq 'latency.discord.media') { $live += $h; continue }  # stable name
        & curl.exe -sk -4 -o NUL --connect-timeout 3 --max-time 4 "https://$h/" 2>$null | Out-Null
        if ($LASTEXITCODE -notin 6, 7, 28) { $live += $h }
        else { Write-Host "  (dropping stale host $h : curl exit $LASTEXITCODE)" -ForegroundColor DarkGray }
    }
    if ($live.Count -eq 0) { $live = @('latency.discord.media') }
    $live
}

# battery: every (host,port) x $Iters -> per-cell rows appended to $acc
function Run-Battery([string]$mode, [hashtable]$acc) {
    foreach ($h in $hostList) {
        Write-Host ("    {0,-8} {1} " -f $mode, $h) -NoNewline -ForegroundColor DarkGray
        foreach ($pt in $Ports) {
            $key = "$mode|$h|$pt"
            if (-not $acc.ContainsKey($key)) { $acc[$key] = [pscustomobject]@{ ms = @(); ok = 0; reset = 0; timeout = 0; other = 0; codes = @{} } }
            $c = $acc[$key]
            for ($i = 0; $i -lt $Iters; $i++) {
                $r = Handshake $h $pt
                switch ($r.verdict) {
                    'ok'      { $c.ok++; $c.ms += $r.ms }
                    'reset'   { $c.reset++ }
                    'timeout' { $c.timeout++ }
                    default   { $c.other++ }
                }
                $c.codes["$($r.exit)"] = 1 + [int]$c.codes["$($r.exit)"]
                Start-Sleep -Milliseconds 120
            }
            Write-Host '.' -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ''
    }
}

# --------------------------------------------------------------------------- #
if (-not $NoEngine -and -not (Test-Admin)) { Fail 'run from an ELEVATED PowerShell (or pass -NoEngine for the baseline-only pass)' }
$exe = if ($NoEngine) { $null } else { Resolve-Exe }
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Fail 'curl.exe not on PATH' }

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot "measure-out\vlat-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Phase 1 (the curl battery) only runs when it was actually asked for: no
# -GuidedJoins, or -Repeat given explicitly alongside it. -GuidedJoins on its
# own goes straight to the guided join/leave loop (the (b) probe-skip check).
$doPhase1 = ($GuidedJoins -le 0) -or $PSBoundParameters.ContainsKey('Repeat')

$hostList = @()
if ($doPhase1) {
    $hostList = if ($Hosts) { $Hosts } else { Harvest-MediaHosts }
}

# `--engine` now resolves the store itself: when the service is installed and has
# a profile for this network it reads/writes %ProgramData%\Bosphorus\profiles
# ("service = authority"), else %LOCALAPPDATA%. -ProfileDir is only for forcing a
# specific directory (it overrides that resolution).
$engineArgs = @()
if ($ProfileDir) { $engineArgs += @('--profile-dir', $ProfileDir) }

$phaseDesc = @()
if ($doPhase1)          { $phaseDesc += "1 (battery x $Repeat)" }
if ($GuidedJoins -gt 0) { $phaseDesc += "2 (guided joins: $GuidedJoins)" }

Write-Host ""
Write-Host "voice-signalling latency / DPI-reset probe" -ForegroundColor Cyan
Write-Host "  exe    : $(if ($exe) { $exe } else { '(baseline only, -NoEngine)' })"
Write-Host "  phase  : $($phaseDesc -join ' + ')"
if ($doPhase1) { Write-Host "  hosts  : $($hostList -join ', ')" }
Write-Host "  ports  : $($Ports -join ', ')"
Write-Host "  iters  : $Iters"
if ($ProfileDir) { Write-Host "  profile: $ProfileDir" -ForegroundColor DarkCyan }
Write-Host "  output : $outDir`n"

$svc = Get-Service -Name Bosphorus -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "stopping Bosphorus service for the run (restart after)." -ForegroundColor Yellow
    Stop-Service Bosphorus -Force -ErrorAction SilentlyContinue
    $script:svcWasRunning = $true
    Start-Sleep -Seconds 2
}

$acc = @{}

if ($doPhase1 -and -not $Hosts) {
    $hostList = Filter-LiveHosts $hostList
    Write-Host "  live hosts: $($hostList -join ', ')`n" -ForegroundColor DarkCyan
}

for ($rep = 1; ($rep -le $Repeat) -and $doPhase1; $rep++) {
    Write-Host "[repeat $rep/$Repeat]" -ForegroundColor Green

    if (-not $NoBaseline) {
        Write-Host "  baseline (no bypass) ..." -ForegroundColor DarkCyan
        Run-Battery 'baseline' $acc
    }

    if (-not $NoEngine) {
        Write-Host "  --engine (bypass active) ..." -ForegroundColor DarkCyan
        $env:RUST_LOG = 'bosphorus::discovery=debug,bosphorus::conntrack=info,bosphorus::strategy=info'
        $life = [int]($hostList.Count * $Ports.Count * $Iters * 1 + 40)
        $ep = Start-Bg $exe (@('--engine', '--secs', "$life") + $engineArgs) "engine-r$rep" $outDir
        Start-Sleep -Seconds 5
        Run-Battery 'engine' $acc
        Stop-Bg $ep
        $env:RUST_LOG = $null
    }
}

# ---- Phase 2: guided joins ------------------------------------------------- #
$joinRows = @()
if ($GuidedJoins -gt 0 -and -not $NoEngine) {
    Write-Host "`n[guided joins] --engine up; join/leave a voice channel on cue ..." -ForegroundColor Green
    $env:RUST_LOG = 'bosphorus::discovery=debug,bosphorus::conntrack=info,bosphorus::strategy=info'
    $gp = Start-Bg $exe (@('--engine', '--secs', "$([int]($GuidedJoins * 35 + 30))") + $engineArgs) 'engine-guided' $outDir
    Start-Sleep -Seconds 5
    for ($j = 1; $j -le $GuidedJoins; $j++) {
        Write-Host "  >> JOIN a voice channel NOW  (join $j/$GuidedJoins) <<" -ForegroundColor Green
        $t0 = [DateTime]::UtcNow
        Start-Sleep -Seconds 22
        Write-Host "  >> LEAVE the voice channel <<" -ForegroundColor Yellow
        $t1 = [DateTime]::UtcNow
        Start-Sleep -Seconds 8
        $joinRows += [pscustomobject]@{ n = $j; from = $t0; to = $t1 }
    }
    Stop-Bg $gp
    $env:RUST_LOG = $null
}

if ($script:svcWasRunning) {
    Write-Host "`nrestarting the Bosphorus service ..." -ForegroundColor Yellow
    Start-Service Bosphorus -ErrorAction SilentlyContinue
}

# ---- parse engine logs for discord.media events -------------------------- #
$allEngine = Get-ChildItem $outDir -Filter 'engine*.out.log' -File -ErrorAction SilentlyContinue |
             ForEach-Object { Get-Content $_.FullName } | ForEach-Object { Strip-Ansi $_ }
$mediaApplied = @($allEngine | Select-String -Pattern 'applied strategy to ClientHello' | Where-Object { $_.Line -match 'discord\.media' })
$mediaSkipped = @($allEngine | Select-String -Pattern 'probe skipped' | Where-Object { $_.Line -match 'discord\.media' })
$mediaClass   = @($allEngine | Select-String -Pattern 'flow classified' | Where-Object { $_.Line -match 'discord\.media' } | ForEach-Object { $_.Line })

function Ts([string]$line) {
    if ($line -match '(\d{4}-\d{2}-\d{2}T[\d:.]+Z)') { try { return [datetime]::Parse($Matches[1]).ToUniversalTime() } catch {} }
    return $null
}

# per guided join: discord.media attempts + resets + span.
# Window is anchored at the JOIN instant and kept shorter than the ~30 s
# join+leave cadence so adjacent joins never double-count the same handshake.
foreach ($jr in $joinRows) {
    $lo = $jr.from.AddSeconds(-2)
    $hi = $jr.from.AddSeconds(26)
    $win = @($mediaClass | Where-Object { $t = Ts $_; $t -and $t -ge $lo -and $t -lt $hi } | ForEach-Object { "$_" })
    $ok    = @($win | Where-Object { $_.Contains('outcome=Success') }).Count
    $reset = @($win | Where-Object { $_ -match 'outcome=(DpiReset|Blackhole|LateReset)' }).Count
    $times = @($win | ForEach-Object { Ts $_ } | Where-Object { $_ } | Sort-Object)
    $span  = if ($times.Count -ge 2) { [math]::Round(($times[-1] - $times[0]).TotalSeconds, 1) } else { 0 }
    $jr | Add-Member -NotePropertyName attempts -NotePropertyValue $win.Count -Force
    $jr | Add-Member -NotePropertyName reset    -NotePropertyValue $reset     -Force
    $jr | Add-Member -NotePropertyName ok       -NotePropertyValue $ok        -Force
    $jr | Add-Member -NotePropertyName spanS    -NotePropertyValue $span      -Force
}

# --------------------------------------------------------------------------- #
$S = New-Object System.Collections.Generic.List[string]
$S.Add('================ MEASURE-VOICE-LATENCY SUMMARY (paste this whole block) ================')
$S.Add("timestamp : $stamp   iters=$Iters repeat=$Repeat  hosts=[$($hostList -join ',')]")
if ($script:svcWasRunning) { $S.Add('note: Bosphorus service was stopped for the run and restarted after.') }
$S.Add('')
if ($doPhase1) {
$S.Add('--- PHASE 1: TLS handshake to *.discord.media per port (DPI-reset probe) ---')
$S.Add(("  {0,-26} {1,5} {2,-9} {3,5} {4,6} {5,6} {6,7} {7,7} {8,7}" -f 'host', 'port', 'mode', 'n', 'ok', 'reset', 'timeout', 'md.ms', 'p90.ms'))
$S.Add('  ' + ('-' * 92))
$modes = @('baseline', 'engine') | Where-Object { $acc.Keys -match "^$_\|" }
foreach ($h in $hostList) {
    foreach ($pt in $Ports) {
        foreach ($m in $modes) {
            $c = $acc["$m|$h|$pt"]
            if (-not $c) { continue }
            $st = Stats $c.ms
            $tot = $c.ok + $c.reset + $c.timeout + $c.other
            $S.Add(("  {0,-26} {1,5} {2,-9} {3,5} {4,6} {5,6} {6,7} {7,7} {8,7}" -f `
                (($h -replace '\.discord\.media$', '')), $pt, $m, $tot, $c.ok, $c.reset, $c.timeout, $st.median, $st.p90))
        }
    }
}
$S.Add('')
$S.Add('--- PHASE 1 verdict ---')
$bReset = 0; $eReset = 0; $bN = 0; $eN = 0
foreach ($k in $acc.Keys) {
    $c = $acc[$k]; $tot = $c.ok + $c.reset + $c.timeout + $c.other
    if ($k -like 'baseline|*') { $bReset += $c.reset; $bN += $tot }
    if ($k -like 'engine|*')   { $eReset += $c.reset; $eN += $tot }
}
$bPct = if ($bN) { [math]::Round(100.0 * $bReset / $bN, 1) } else { 0 }
$ePct = if ($eN) { [math]::Round(100.0 * $eReset / $eN, 1) } else { 0 }
$S.Add("  baseline TLS-reset rate : $bReset / $bN  ($bPct %)")
$S.Add("  --engine TLS-reset rate : $eReset / $eN  ($ePct %)")
$S.Add("  engine: 'applied strategy' to discord.media : $($mediaApplied.Count)   'probe skipped' : $($mediaSkipped.Count)")
if ($bPct -ge 5 -and $ePct -lt $bPct / 2) {
    $S.Add('  => DPI DOES reset *.discord.media signalling intermittently, and the bypass cuts it')
    $S.Add('     down sharply. THIS is the "sometimes 5 s+" cause; (a)+(b) address it.')
} elseif ($bPct -lt 5 -and $ePct -lt 5) {
    $S.Add('  => no meaningful reset on the signalling path this run. Re-run with a larger -Repeat')
    $S.Add('     (e.g. 30) to catch the intermittent window, or the delay is on the UDP media /')
    $S.Add('     Discord app-retry side, not our TLS path.')
} else {
    $S.Add('  => mixed / inconclusive - see the per-port table above.')
}
$S.Add('')
} # end if ($doPhase1)
if ($joinRows.Count) {
    $S.Add('--- PHASE 2: guided voice joins (per-join *.discord.media signalling) ---')
    $S.Add(("  {0,4} {1,9} {2,7} {3,6} {4,8}" -f 'join', 'attempts', 'reset', 'ok', 'span(s)'))
    foreach ($jr in $joinRows) {
        $S.Add(("  {0,4} {1,9} {2,7} {3,6} {4,8}" -f $jr.n, $jr.attempts, $jr.reset, $jr.ok, $jr.spanS))
    }
    $slow = @($joinRows | Where-Object { $_.spanS -ge 3 -or $_.reset -gt 0 }).Count
    $S.Add("  slow / reset-hit joins: $slow / $($joinRows.Count)")
    $S.Add('  (fast join = 1 attempt, ok, <1s span. slow = >=2 attempts and/or a DpiReset / LateReset.)')
    foreach ($l in ($mediaClass | Select-Object -Last 12)) { $S.Add("    $l") }
    $S.Add('')
}
$S.Add('--- how to catch the slow case ---')
$S.Add('  Phase 1 unattended:  ... -Repeat 30        (leave it running; ~1 handshake/120ms)')
$S.Add('  Phase 2 correlated:   ... -GuidedJoins 8   (join/leave 8x; watch which joins go slow)')
$S.Add('======================================================================================')

$txt = ($S -join "`r`n")
$txt | Set-Content -Path (Join-Path $outDir 'SUMMARY.txt') -Encoding utf8
Write-Host ""
Write-Host $txt
Write-Host ""
Write-Host "saved: $(Join-Path $outDir 'SUMMARY.txt')" -ForegroundColor Green
