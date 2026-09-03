<#
.SYNOPSIS
  Live check of the "regional Discord gateways rotate, each gets exactly one
  naked Probe connection, and Probe never consults a seed" theory.

  Cold-starts Discord under --engine (discovery=debug + conntrack=info +
  strategy=info) and answers, from the real traffic:

    Q1  how many distinct gateway-us-east1-{a,b,c,d,...}.discord.gg hosts appear
    Q2  per host: how many actual connections (distinct client_port with a
        verdict). 1 each  => theory holds.  >=2 on any  => partially refuted.
    Q3  Probe-doesn't-seed evidence: were there ANY "seeded candidate offered"
        lines for a gateway-us-east1-* host, and did any of them ever leave
        Probe/tried=0 ? (theory: 0 seeds for them, all stuck at tried=0 while
        gateway.discord.gg is Active+strategy so a seed WAS available)

  Prints ONE summary block. Paste it back.

.NOTES
  ELEVATED PowerShell, repo root:
      powershell -ExecutionPolicy Bypass -File .\scripts\verify-gateway-rotation.ps1

  It force-closes Discord for a cold start (relaunches it), runs --engine for
  ~$WatchSecs, then stops. No voice interaction needed - just let Discord open
  and reach the server list. PS 5.1 compatible. Restarts the Bosphorus service
  if it was running.
#>

[CmdletBinding()]
param(
    [int]$WatchSecs = 120,
    [string]$Exe,
    [switch]$KeepDiscord   # skip the cold-start kill (use the already-running Discord)
)

$ErrorActionPreference = 'Stop'
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
function Strip-Ansi([string]$s) { return ([regex]::Replace($s, "\[[0-9;]*m", "")) }

function Start-Discord {
    $upd = Join-Path $env:LOCALAPPDATA 'Discord\Update.exe'
    if (Test-Path $upd) { Start-Process -FilePath $upd -ArgumentList '--processStart', 'Discord.exe' | Out-Null; return "Update.exe" }
    $base = Join-Path $env:LOCALAPPDATA 'Discord'
    if (Test-Path $base) {
        $app = Get-ChildItem $base -Filter 'app-*' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($app) { $d = Join-Path $app.FullName 'Discord.exe'; if (Test-Path $d) { Start-Process $d | Out-Null; return $d } }
    }
    $c = Get-Command Discord.exe -ErrorAction SilentlyContinue
    if ($c) { Start-Process $c.Source | Out-Null; return $c.Source }
    return $null
}

# --------------------------------------------------------------------------- #
if (-not (Test-Admin)) { Fail 'run from an ELEVATED (Administrator) PowerShell' }
$exe = Resolve-Exe
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot "measure-out\gwrot-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host ""
Write-Host "gateway-rotation verification" -ForegroundColor Cyan
Write-Host "  exe    : $exe"
Write-Host "  watch  : ${WatchSecs}s"
Write-Host "  output : $outDir`n"

$svc = Get-Service -Name Bosphorus -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "stopping Bosphorus service for the run (restart after)." -ForegroundColor Yellow
    Stop-Service Bosphorus -Force -ErrorAction SilentlyContinue
    $script:svcWasRunning = $true
    Start-Sleep -Seconds 2
}

if (-not $KeepDiscord) {
    $d = @(Get-Process -Name Discord -ErrorAction SilentlyContinue)
    if ($d.Count) {
        Write-Host "cold start: closing $($d.Count) Discord process(es) ..." -ForegroundColor Yellow
        $d | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
    }
}

$env:RUST_LOG = 'bosphorus::discovery=debug,bosphorus::conntrack=info,bosphorus::strategy=info'
$engineSecs = $WatchSecs + 10
$o = Join-Path $outDir 'engine.out.log'
$e = Join-Path $outDir 'engine.err.log'
Write-Host "[engine] --engine --secs $engineSecs ..." -ForegroundColor Green
$p = Start-Process -FilePath $exe -ArgumentList @('--engine', '--secs', "$engineSecs") -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
$script:bg += $p
Start-Sleep -Seconds 5

$how = Start-Discord
if (-not $how) { Write-Host "  Discord.exe not found - open it yourself NOW." -ForegroundColor Yellow }
else { Write-Host "  launched Discord ($how) - let it update, log in, reach the server list." -ForegroundColor DarkCyan }

Write-Host "  watching for ${WatchSecs}s ..." -ForegroundColor DarkCyan
Start-Sleep -Seconds $WatchSecs

Write-Host "  waiting for --engine to finish its window and print its summary ..." -ForegroundColor DarkCyan
if (-not $p.WaitForExit(45000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
$env:RUST_LOG = $null

if ($script:svcWasRunning) {
    Write-Host "restarting the Bosphorus service ..." -ForegroundColor Yellow
    Start-Service Bosphorus -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------------------- #
#  parse
# --------------------------------------------------------------------------- #
$raw = @()
if (Test-Path $o) { $raw += Get-Content $o }
if (Test-Path $e) { $raw += Get-Content $e }
$lines = $raw | ForEach-Object { Strip-Ansi $_ }

# ANY Discord gateway / voice host - not just us-east1:
#   gateway-<region>-<letter>.discord.gg   (us-east1, us-west1, europe, russia, india, ...)
#   <node>.discord.media                   (rotating voice RTC / signalling host)
$reRegGw   = 'gateway-[a-z0-9]+(?:-[a-z0-9]+)*\.discord\.gg'   # has a dash after "gateway"
$rePlainGw = '\bgateway\.discord\.gg\b'                        # the main gateway (seed source)
$reMedia   = '[a-z0-9][a-z0-9.-]*\.discord\.media'

# Generic per-host accounting over a set of hostnames pulled from the log by $rx.
function Account($rx) {
    $seen = @{}
    foreach ($ln in $lines) { foreach ($m in [regex]::Matches($ln, $rx)) { $seen[$m.Value] = $true } }
    $hh = @($seen.Keys | Sort-Object)
    $tbl = @{}
    foreach ($h in $hh) { $tbl[$h] = [pscustomobject]@{ ports=@{}; verdicts=@(); applied=0; seeded=@(); events=@(); progress=@() } }
    foreach ($ln in $lines) {
        $m = [regex]::Match($ln, $rx)
        if (-not $m.Success) { continue }
        $rec = $tbl[$m.Value]
        if (-not $rec) { continue }
        if ($ln -match 'flow classified') {
            if ($ln -match 'client_port=([0-9]+)') { $rec.ports[$Matches[1]] = $true }
            if ($ln -match 'outcome=([A-Za-z]+)')  { $rec.verdicts += $Matches[1] }
        }
        if ($ln -match 'applied strategy to ClientHello')     { $rec.applied++ }
        if ($ln -match 'seeded candidate offered')            { $rec.seeded  += ($ln -replace '.*seeded candidate offered', 'seeded') }
        if ($ln -match 'discovery update .*event=([A-Za-z]+)') { $rec.events += $Matches[1] }
        if ($ln -match 'discovery progress .*phase=([A-Za-z]+) .*tried=([0-9]+)') { $rec.progress += "$($Matches[1])/tried=$($Matches[2])" }
    }
    return [pscustomobject]@{ hosts = $hh; tbl = $tbl }
}

function Emit-HostTable($acc, [string]$title) {
    $S.Add("--- $title : $($acc.hosts.Count) host(s) ---")
    if ($acc.hosts.Count -eq 0) { $S.Add('  (none seen)'); return @() }
    $S.Add(("  {0,-38} {1,6} {2,-20} {3,7}  {4}" -f 'host', 'conns', 'verdicts', 'applied', 'phase/tried'))
    $S.Add('  ' + ('-' * 96))
    $two = @()
    foreach ($h in $acc.hosts) {
        $r = $acc.tbl[$h]
        $nc = $r.ports.Keys.Count
        if ($nc -ge 2) { $two += $h }
        $vs = if ($r.verdicts.Count) { ($r.verdicts | Group-Object | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ',' } else { '-' }
        $pr = if ($r.progress.Count) { ($r.progress | Select-Object -Unique) -join ' ' } else { '-' }
        $S.Add(("  {0,-38} {1,6} {2,-20} {3,7}  {4}" -f $h, $nc, $vs, $r.applied, $pr))
        if ($r.events.Count) { $S.Add("       events: $((($r.events | Group-Object | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', '))") }
        foreach ($sd in $r.seeded) { $S.Add("       $sd") }
    }
    return $two
}

$accGw    = Account $reRegGw
$accMedia = Account $reMedia

$plainClass  = @($lines | Select-String -Pattern "flow classified .*server=`"gateway\.discord\.gg`"" | ForEach-Object { Strip-Ansi $_.Line })
$plainActive = [bool](@($lines | Select-String -Pattern 'gateway\.discord\.gg.*Active|server=gateway\.discord\.gg.*Success').Count)
$seedForGw   = @($lines | Select-String -Pattern 'seeded candidate offered' | Where-Object { $_.Line -match $reRegGw -or $_.Line -match $reMedia } | ForEach-Object { Strip-Ansi $_.Line })
$allSeed     = @($lines | Select-String -Pattern 'seeded candidate offered' | ForEach-Object { Strip-Ansi $_.Line })

# engine exit discovery summary
$sum = @()
$arr = $raw | ForEach-Object { Strip-Ansi $_ }
$si = ($arr | Select-String -Pattern 'discovery summary|kesif ozeti|keşif özeti' | Select-Object -First 1)
if ($si) { $sum = @($arr[($si.LineNumber - 1)..([math]::Min($arr.Count - 1, $si.LineNumber + 90))] | Where-Object { $_ -match 'gateway|discord' }) }

# --------------------------------------------------------------------------- #
$S = New-Object System.Collections.Generic.List[string]
$S.Add('================ VERIFY-GATEWAY-ROTATION SUMMARY (paste this whole block) ================')
$S.Add("timestamp : $stamp")
$S.Add("exe       : $exe   watch=${WatchSecs}s")
$S.Add("engine self-terminated (summary captured): $([bool]$si)")
$S.Add('note: --engine sees TCP:443 only. A voice host on 2083/2096 shows up with conns=0 here')
$S.Add('      (SNI still logged) - use measure-voice.ps1 --observe for its real port/verdict.')
$S.Add('')
$twoGw    = Emit-HostTable $accGw    'REGIONAL GATEWAYS  (gateway-<region>-<x>.discord.gg, ALL regions)'
$S.Add('')
$twoMedia = Emit-HostTable $accMedia 'VOICE HOSTS        (*.discord.media)'
$S.Add('')
$S.Add('--- seeding / seed-availability ---')
$S.Add("  main gateway.discord.gg  flow-classified : $($plainClass.Count)   active-ish this run: $plainActive")
foreach ($l in ($plainClass | Select-Object -First 4)) { $S.Add("     $l") }
$S.Add("  'seeded candidate offered' for a regional gateway / media host : $($seedForGw.Count)   (theory predicts 0)")
foreach ($l in $seedForGw) { $S.Add("     $l") }
$S.Add("  'seeded candidate offered' total (any host) : $($allSeed.Count)")
foreach ($l in ($allSeed | Select-Object -First 10)) { $S.Add("     $l") }
$S.Add('')
if ($sum.Count) {
    $S.Add('--- engine discovery summary on exit (all discord/gateway rows) ---')
    foreach ($l in $sum) { $S.Add("  $l") }
    $S.Add('')
}
$liveGw    = @($accGw.hosts    | Where-Object { $accGw.tbl[$_].ports.Keys.Count -ge 1 })
$liveMedia = @($accMedia.hosts | Where-Object { $accMedia.tbl[$_].ports.Keys.Count -ge 1 })
$S.Add('--- VERDICT ---')
if ($liveGw.Count -eq 0 -and $liveMedia.Count -eq 0) {
    $S.Add('  INCONCLUSIVE for the rotation theory - NO live tcp:443 connection to any regional')
    $S.Add('  gateway OR media host this run (only stale disk state in the progress lines).')
    $S.Add('  Discord used the main gateway.discord.gg only. To force regional/media traffic:')
    $S.Add('  join a voice channel, or switch server / voice region, DURING the watch; re-run')
    $S.Add('  with a longer -WatchSecs. (A media host on port 2096 also lands here as conns=0.)')
} else {
    if ($liveGw.Count)    { $S.Add("  regional gateways with a live connection this run : $($liveGw -join ', ')") }
    if ($liveMedia.Count) { $S.Add("  media hosts with a live tcp:443 connection        : $($liveMedia -join ', ')") }
    if (($twoGw + $twoMedia).Count -eq 0 -and $seedForGw.Count -eq 0) {
        $S.Add('  Consistent with the theory: each got exactly ONE connection and NO seed was offered.')
        $S.Add('  => Phase 2 Probe-skip / seed-on-first-connect is justified.')
    } else {
        $S.Add('  PARTIALLY REFUTES the theory:')
        if (($twoGw + $twoMedia).Count) { $S.Add("   - >=2 connections: $((($twoGw + $twoMedia)) -join ', ')") }
        if ($seedForGw.Count)           { $S.Add("   - a seed WAS offered ($($seedForGw.Count) lines) - Discover phase reached") }
        $S.Add('   => re-examine before Phase 2.')
    }
}
$S.Add('=======================================================================================')

$txt = ($S -join "`r`n")
$txt | Set-Content -Path (Join-Path $outDir 'SUMMARY.txt') -Encoding utf8
Write-Host ""
Write-Host $txt
Write-Host ""
Write-Host "saved: $(Join-Path $outDir 'SUMMARY.txt')" -ForegroundColor Green
