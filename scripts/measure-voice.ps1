<#
.SYNOPSIS
  Phase 1 diagnosis - Discord VOICE-channel join latency (~15 s) + message / gateway
  load latency. Splits the two symptoms across their real protocol paths.

  KEY POINT: on a censored line Discord cannot even finish its updater without the
  bypass, so this runs  --engine  (bypass active) and  --observe  (pure sniff of
  ALL tcp+udp, never mutates) AT THE SAME TIME, auto-launches Discord, and walks
  you through joining a voice channel twice. Then it classifies:
     - *.discord.media over tcp:443   -> voice SIGNALLING WebSocket   (IN scope)
     - udp to non-53 / high ports      -> voice MEDIA (SRTP/RTP)       (NOT in scope)
     - udp:443 QUIC Initial            -> QUIC-drop territory
  and shows whether #1/#4 seeding takes the regional gateways / *.discord.media
  Active in ~1 connection (via_seed) instead of a full 166-strategy sweep.

  Prints ONE summary block. Paste that block back.

.NOTES
  Run from an ELEVATED PowerShell at the repo root:
      powershell -ExecutionPolicy Bypass -File .\scripts\measure-voice.ps1

  It launches Discord for you (override with -DiscordExe, disable with -NoLaunch).
  Your only manual actions: follow the  ">> NOW: <instruction> <<"  cues in the
  Discord app (join / leave a voice channel).

  -Step engine   : engine only, no sniffer.
  -Step observe  : sniffer only, no engine (raw blocked picture; Discord may not
                   fully connect on a censored line).
  -Step all      : both together (default, recommended).

  Windows PowerShell 5.1 compatible. If the Bosphorus SERVICE is running it is
  stopped for the run and restarted afterwards.
#>

[CmdletBinding()]
param(
    [ValidateSet('all', 'observe', 'engine')]
    [string]$Step             = 'all',
    [int]$ObserveSecs         = 120,
    [int]$EngineWarmupSecs    = 30,   # engine up + Discord launching before the sniffer starts
    [string]$Exe,
    [string]$DiscordExe,
    [switch]$NoLaunch
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
    Fail "bosphorus.exe not found - run: cargo build --release"
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
    Start-Sleep -Milliseconds 800
}

function Find-Discord {
    if ($DiscordExe) { if (Test-Path $DiscordExe) { return $DiscordExe } ; Fail "-DiscordExe '$DiscordExe' not found" }
    $upd = Join-Path $env:LOCALAPPDATA 'Discord\Update.exe'
    if (Test-Path $upd) { return $upd }
    $base = Join-Path $env:LOCALAPPDATA 'Discord'
    if (Test-Path $base) {
        $app = Get-ChildItem $base -Filter 'app-*' -Directory -ErrorAction SilentlyContinue |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($app) { $d = Join-Path $app.FullName 'Discord.exe'; if (Test-Path $d) { return $d } }
    }
    $c = Get-Command Discord.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

function Start-Discord {
    if ($NoLaunch) { Write-Host "  -NoLaunch: leaving Discord to you" -ForegroundColor Yellow; return }
    $run = Get-Process -Name Discord -ErrorAction SilentlyContinue
    if ($run) { Write-Host "  Discord already running (pid $($run[0].Id))" -ForegroundColor DarkCyan; return }
    $path = Find-Discord
    if (-not $path) {
        Write-Host "  Discord.exe not found - open it yourself now." -ForegroundColor Yellow
        return
    }
    try {
        if ($path -match 'Update\.exe$') {
            Start-Process -FilePath $path -ArgumentList '--processStart', 'Discord.exe' | Out-Null
        } else {
            Start-Process -FilePath $path | Out-Null
        }
        Write-Host "  launched Discord: $path" -ForegroundColor DarkCyan
    } catch {
        Write-Host "  could not launch Discord ($_) - open it yourself now." -ForegroundColor Yellow
    }
}

# Bounded ENTER gate: waits up to $capSecs for a keypress, never blocks a
# background capture. Degrades to a short sleep when stdin is redirected.
function Wait-Key([string]$msg, [int]$capSecs) {
    if ([Console]::IsInputRedirected) { Start-Sleep -Seconds ([math]::Min($capSecs, 15)); return }
    Write-Host "  $msg  (press ENTER, or auto-continue in ${capSecs}s)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds($capSecs)
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch {}
    while ((Get-Date) -lt $deadline) {
        try { if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); break } } catch { Start-Sleep -Seconds 1 }
        Start-Sleep -Milliseconds 200
    }
}

function Read-NewestProfile {
    @(
        (Join-Path $env:LOCALAPPDATA 'Bosphorus\profiles'),
        (Join-Path $env:ProgramData  'Bosphorus\profiles')
    ) | Where-Object { Test-Path $_ } |
      ForEach-Object { Get-ChildItem $_ -Filter *.json -File -ErrorAction SilentlyContinue } |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Dump-DiscordTargets($profFile) {
    if (-not $profFile) { return @('  (no profile on disk yet)') }
    try { $pj = Get-Content -Raw $profFile.FullName | ConvertFrom-Json } catch { return @("  (profile parse failed: $_)") }
    $out = @("  profile: $($profFile.Name)  ($($profFile.LastWriteTime))")
    $rx = 'discord|\.gg$|\.gg/|discord\.media|\.media$'
    $hit = @($pj.targets | Where-Object { $_.key -match $rx } | Sort-Object key)
    if ($hit.Count -eq 0) { $out += '  (no discord/media targets)'; return $out }
    foreach ($t in $hit) {
        $act = if ($null -ne $t.active) { 'Active+strategy' } else { '-' }
        $out += ("    {0,-40} {1,-9} {2}" -f $t.key, $t.phase, $act)
    }
    $out += ("  -> *.discord.media targets: {0}" -f @($hit | Where-Object { $_.key -match 'discord\.media' }).Count)
    return $out
}

# --------------------------------------------------------------------------- #
if (-not (Test-Admin)) { Fail 'run from an ELEVATED (Administrator) PowerShell' }
$exe = Resolve-Exe

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot "measure-out\voice-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host ""
Write-Host "Bosphorus voice/gateway latency diagnosis" -ForegroundColor Cyan
Write-Host "  exe    : $exe"
Write-Host "  step   : $Step   warmup=${EngineWarmupSecs}s   (observe window auto-sized to the guided cues)"
Write-Host "  output : $outDir"
Write-Host ""

$svc = Get-Service -Name Bosphorus -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "Bosphorus service is Running - stopping it for the run (restart after)." -ForegroundColor Yellow
    Stop-Service Bosphorus -Force -ErrorAction SilentlyContinue
    $script:svcWasRunning = $true
    Start-Sleep -Seconds 2
}

$before = Dump-DiscordTargets (Read-NewestProfile)
Write-Host "--- discord/media targets BEFORE ---" -ForegroundColor Green
$before | ForEach-Object { Write-Host $_ }

$engineProc = $null
$obsProc    = $null
$gateCap    = 45
$cue1 = 45; $cueGap = 12; $cue2 = 35; $cueEnd = 12
# --observe prints its table ONLY when --secs elapses, so it MUST outlast the
# whole guided window and self-terminate (we Wait-Process it, never force-kill).
$computed = 4 + $EngineWarmupSecs + $gateCap + ($cue1 + $cueGap + $cue2 + $cueEnd) + 15
$obsSecs  = [math]::Max($ObserveSecs, $computed)

# --- sniffer FIRST (solo handle, catches the whole Discord startup) --------- #
if ($Step -in @('all', 'observe')) {
    Write-Host "`n[observe] starting --observe --secs $obsSecs (pure sniff, no packet touched) ..." -ForegroundColor Green
    $obsProc = Start-Bg $exe @('--observe', '--secs', "$obsSecs") 'observe' $outDir
    Start-Sleep -Seconds 3
}

# --- engine (bypass) so Discord can actually get past 'Update failed' ------- #
if ($Step -in @('all', 'engine')) {
    Write-Host "[engine] starting --engine (bypass active) ..." -ForegroundColor Green
    $env:RUST_LOG = 'bosphorus::discovery=debug,bosphorus::conntrack=info,bosphorus::strategy=info'
    $engineProc = Start-Bg $exe @('--engine', '--secs', "900") 'engine' $outDir
    Start-Sleep -Seconds 5
}

# --- launch Discord, let it update / log in / render the server list -------- #
Write-Host "[discord] launching Discord, letting it come online (~${EngineWarmupSecs}s) ..." -ForegroundColor Green
Start-Discord
if ($Step -eq 'observe') {
    Write-Host "  NOTE: -Step observe has NO bypass - on a censored line Discord may stay on 'Update failed'." -ForegroundColor Yellow
}
Start-Sleep -Seconds $EngineWarmupSecs

# --- guided voice-channel join x2 --------------------------------------- #
Wait-Key 'When Discord is OPEN and the server list / voice channels are visible:' $gateCap
Write-Host ""
Write-Host "  >> NOW: JOIN A VOICE CHANNEL. Stay in it, TALK for the whole time. (~${cue1}s) <<" -ForegroundColor Green
$joinAt1 = [DateTime]::Now
Start-Sleep -Seconds $cue1
Write-Host "  >> NOW: LEAVE the voice channel. (~${cueGap}s) <<" -ForegroundColor Yellow
Start-Sleep -Seconds $cueGap
Write-Host "  >> NOW: JOIN a voice channel AGAIN - 2nd sample. Talk. (~${cue2}s) <<" -ForegroundColor Green
$joinAt2 = [DateTime]::Now
Start-Sleep -Seconds $cue2
Write-Host "  >> NOW: LEAVE. <<" -ForegroundColor Yellow
Start-Sleep -Seconds $cueEnd
Write-Host "  cues done - waiting for --observe to finish its window and print ..." -ForegroundColor DarkCyan

if ($obsProc) {
    if (-not $obsProc.WaitForExit(90000)) {
        Write-Host "  --observe did not self-exit in time; stopping it (report may be short)." -ForegroundColor Yellow
        Stop-Bg $obsProc
    }
}
Stop-Bg $engineProc
$env:RUST_LOG = $null

if ($script:svcWasRunning) {
    Write-Host "`nrestarting the Bosphorus service ..." -ForegroundColor Yellow
    Start-Service Bosphorus -ErrorAction SilentlyContinue
}

$after = Dump-DiscordTargets (Read-NewestProfile)

# --------------------------------------------------------------------------- #
#  parse --observe table
# --------------------------------------------------------------------------- #
$obsRaw = if (Test-Path (Join-Path $outDir 'observe.out.log')) { Get-Content (Join-Path $outDir 'observe.out.log') } else { @() }
$obsRows = @()
$inTable = $false
$obsHasReport = [bool]($obsRaw | Select-String -Pattern 'SONUC' -Quiet)
foreach ($ln in $obsRaw) {
    if ($ln -match 'SONUC') { $inTable = $true; continue }
    if (-not $inTable) { continue }
    if ($ln -match '^={5,}') { break }
    if ($ln -match '^\s*hedef|^\s*-{5,}|^\s*$|^toplam|^akis|^Not:') { continue }
    $obsRows += $ln.TrimEnd()
}
$obsTotals = @($obsRaw | Select-String -Pattern '^toplam|^akis' | ForEach-Object { $_.Line.Trim() })
function Col($line, $i) { $c = @(($line -split '\s+') | Where-Object { $_ }); if ($i -lt $c.Count) { return $c[$i] } ; return '' }

$mediaTcp = @($obsRows | Where-Object { $_ -match 'discord\.media' -and $_ -match '\btcp\b' })
$mediaOth = @($obsRows | Where-Object { $_ -match 'discord\.media' -and $_ -notmatch '\btcp\b' })
$ggTcp    = @($obsRows | Where-Object { $_ -match 'discord\.gg' -and $_ -match '\btcp\b' })
$udpAll   = @($obsRows | Where-Object { $_ -match '\budp\b' })
$udpNon53 = @($udpAll | Where-Object { (Col $_ 1) -ne '53' })
$udpQuic  = @($udpAll | Where-Object { $_ -match 'quicv=' })
$udpHigh  = @($udpNon53 | Where-Object { $p = 0; [void][int]::TryParse((Col $_ 1), [ref]$p); $p -ge 20000 })
$udpBack  = @($udpNon53 | Where-Object { $_ -match '\bOK\b|\bmixed\b' })

# --------------------------------------------------------------------------- #
#  parse engine log
# --------------------------------------------------------------------------- #
$eo = if (Test-Path (Join-Path $outDir 'engine.out.log')) { Get-Content (Join-Path $outDir 'engine.out.log') } else { @() }
$ee = if (Test-Path (Join-Path $outDir 'engine.err.log')) { Get-Content (Join-Path $outDir 'engine.err.log') } else { @() }
$log = @($eo) + @($ee)
$seed   = @($log | Select-String -Pattern 'seeded candidate offered' | ForEach-Object { $_.Line.Trim() })
$promo  = @($log | Select-String -Pattern 'Promoted \{|event=Promoted' | ForEach-Object { $_.Line.Trim() })
$prog   = @($log | Select-String -Pattern 'discovery progress' | Where-Object { $_.Line -match 'discord\.gg|discord\.media' } | ForEach-Object { $_.Line.Trim() })
$mApplied = @($log | Select-String -Pattern 'applied strategy to ClientHello' | Where-Object { $_.Line -match 'discord\.media' } | ForEach-Object { $_.Line.Trim() })
$mClass   = @($log | Select-String -Pattern 'flow classified' | Where-Object { $_.Line -match 'discord\.media' } | ForEach-Object { $_.Line.Trim() })
$ggClass  = @($log | Select-String -Pattern 'flow classified' | Where-Object { $_.Line -match 'discord\.gg' } | ForEach-Object { $_.Line.Trim() })
$anyDiscordFlow = @($log | Select-String -Pattern 'flow classified' | Where-Object { $_.Line -match 'discord' } | ForEach-Object { $_.Line.Trim() })
$enSummary = @()
$si = ($eo | Select-String -Pattern 'discovery summary|kesif ozeti|keşif özeti' | Select-Object -First 1)
if ($si) { $enSummary = @($eo[($si.LineNumber - 1)..([math]::Min($eo.Count - 1, $si.LineNumber + 70))] | Where-Object { $_ -match 'discord|media|gateway|OK \[|!! \[|\.\. \[' }) }

# --------------------------------------------------------------------------- #
$S = New-Object System.Collections.Generic.List[string]
$S.Add('================ MEASURE-VOICE SUMMARY (paste this whole block back) ================')
$S.Add("timestamp : $stamp")
$S.Add("exe       : $exe")
$S.Add("outdir    : $outDir")
$S.Add("step      : $Step   warmup=${EngineWarmupSecs}s")
if ($script:svcWasRunning) { $S.Add('note: Bosphorus service was stopped for the run and restarted after.') }
if ($Step -in @('all', 'observe') -and -not $obsHasReport) {
    $S.Add('!! --observe produced NO report (process ended before printing its table). Re-run;')
    $S.Add('   if it keeps happening the two WinDivert handles are colliding - say so.')
}
if ($Step -in @('all', 'engine') -and $anyDiscordFlow.Count -lt 4) {
    $S.Add("!! only $($anyDiscordFlow.Count) discord flow(s) classified by --engine - Discord was probably NOT")
    $S.Add('   fully exercised (not logged in? no server open? voice channel never actually joined?).')
    $S.Add('   The voice verdict below is INCONCLUSIVE if this fires.')
}
$dpg = @(Get-Process -Name Discord -ErrorAction SilentlyContinue)
$S.Add("discord running at end: $([bool]$dpg.Count)")
$S.Add('')
$S.Add('--- discord / media targets in profile ---')
$S.Add(' BEFORE:'); $before | ForEach-Object { $S.Add("  $_") }
$S.Add(' AFTER :'); $after  | ForEach-Object { $S.Add("  $_") }
$S.Add('')

if ($Step -in @('all', 'observe')) {
    $S.Add('--- [observe] full flow table ---')
    foreach ($t in $obsTotals) { $S.Add("  $t") }
    if (-not $obsHasReport) { $S.Add('  (--observe never printed its table this run - see the !! note above)') }
    elseif ($obsRows.Count -eq 0) { $S.Add('  (table printed but empty - no tcp/udp seen; handle collision or Discord idle)') }
    foreach ($r in $obsRows) { $S.Add("  $r") }
    $S.Add('')
    $S.Add('--- [observe] classification ---')
    $S.Add("  *.discord.media tcp:443 (voice SIGNALLING WSS, IN scope) : $($mediaTcp.Count)")
    foreach ($r in $mediaTcp) { $S.Add("     $r") }
    if ($mediaOth.Count) { $S.Add("  *.discord.media non-tcp                                  : $($mediaOth.Count)"); foreach ($r in $mediaOth) { $S.Add("     $r") } }
    $S.Add("  discord.gg tcp:443 (gateway / regional gateway)          : $($ggTcp.Count)")
    foreach ($r in $ggTcp) { $S.Add("     $r") }
    $S.Add("  udp total / non-53 / high-port>=20000 / with-return-data : $($udpAll.Count) / $($udpNon53.Count) / $($udpHigh.Count) / $($udpBack.Count)")
    foreach ($r in $udpHigh) { $S.Add("     HIGH-UDP  $r") }
    foreach ($r in ($udpNon53 | Where-Object { $udpHigh -notcontains $_ })) { $S.Add("     udp       $r") }
    if ($udpQuic.Count) { $S.Add("  udp QUIC-Initial flows                                   : $($udpQuic.Count)"); foreach ($r in $udpQuic) { $S.Add("     $r") } }
    $S.Add('')
}

if ($Step -in @('all', 'engine')) {
    $S.Add('--- [engine] #1/#4 seeding + discord.media discovery ---')
    $S.Add("  'seeded candidate offered' : $($seed.Count)")
    foreach ($l in ($seed | Select-Object -First 25)) { $S.Add("     $l") }
    $S.Add("  'Promoted' events           : $($promo.Count)   (want via_seed: Some(DomainSibling|HouseStrategy))")
    foreach ($l in ($promo | Select-Object -First 25)) { $S.Add("     $l") }
    $S.Add("  discovery progress (discord.gg / discord.media) : $($prog.Count)")
    foreach ($l in (@($prog | Select-Object -First 8) + @($prog | Select-Object -Last 8) | Select-Object -Unique)) { $S.Add("     $l") }
    $S.Add("  *.discord.media : strategy applied $($mApplied.Count)x | flow classified $($mClass.Count)x")
    foreach ($l in ($mClass | Select-Object -First 12)) { $S.Add("     $l") }
    $S.Add("  discord.gg flow classified : $($ggClass.Count)x")
    foreach ($l in ($ggClass | Select-Object -First 12)) { $S.Add("     $l") }
    if ($enSummary.Count) { $S.Add('  engine discovery summary on exit:'); foreach ($l in $enSummary) { $S.Add("     $l") } }
    $S.Add('')
}

$S.Add('--- READING GUIDE ---')
$S.Add('  #1/#4 WORKS if a gateway-us-east1-*.discord.gg or *.discord.media line shows')
$S.Add('     "seeded candidate offered ... tier=DomainSibling|HouseStrategy" + a matching')
$S.Add('     "Promoted { ... via_seed: Some(...) }"  = Active in ~1 connection, no full sweep.')
$S.Add('  VOICE SIGNALLING (in scope) = *.discord.media tcp:443 verdict.')
$S.Add('     DpiReset/Blackhole -> the ~15 s is (partly) our cold-start on this rotating host;')
$S.Add('                          #1/#4 / a media-specific seed is the fix.')
$S.Add('     OK/mixed           -> signalling is not the bottleneck.')
$S.Add('  VOICE MEDIA (NOT in scope today) = high-port udp verdict.')
$S.Add('     with-return-data (OK/mixed) -> UDP media flows fine; 15 s is NOT the media path.')
$S.Add('     outbound-only / 0 return     -> Vodafone drops the UDP media; nothing in the')
$S.Add('                                     TCP:443 architecture can touch it -> separate UDP milestone.')
$S.Add('  MESSAGES/GATEWAY = discord.gg tcp:443 verdict + regional-gateway phase (all in scope).')
$S.Add('===================================================================================')

$txt = ($S -join "`r`n")
$txt | Set-Content -Path (Join-Path $outDir 'SUMMARY.txt') -Encoding utf8
Write-Host ""
Write-Host $txt
Write-Host ""
Write-Host "saved: $(Join-Path $outDir 'SUMMARY.txt')" -ForegroundColor Green
