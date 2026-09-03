<#
.SYNOPSIS
  §5 speed / latency measurement for Bosphorus discovery (D analysis sub-part).

  Automates the four manual steps:
    1. Freeze the current network's discovery profile (discord SNIs: phase/active/scores/quality).
    2. Run auto-discovery for a window with verbose tracing while you launch Discord,
       then scan the log for the "ClientHello retransmit after strategy already applied"
       smoking gun and blackhole/timeout counts.
    3. For the promoted strategy index (read automatically from the profile) plus a set
       of neighbours, run a forced `--strategy grid:<i>` engine and time `curl`
       TLS handshakes (time_appconnect) against each Active discord SNI.
    4. Run `--observe` for a window while you launch Discord, to see the burst width
       (distinct SNIs, how many get RST).

  Prints ONE summary block at the end. Copy that block back.

.NOTES
  Run from an ELEVATED PowerShell, from the repo root:
      .\scripts\measure-speed.ps1

  Your only manual actions: run this, and open/close the Discord desktop app when the
  script prints  ">> OPEN DISCORD NOW <<"  /  ">> you can close Discord <<".

  Windows PowerShell 5.1 compatible. No machine changes are made. If the Bosphorus
  SERVICE is running it will confound the measurement - the script warns and pauses.
#>

[CmdletBinding()]
param(
    [int]$Secs = 30,            # step 2 auto-discovery window
    [int]$ObserveSecs = 30,     # step 4 --observe window
    [int]$CurlIterations = 6,   # curl handshakes per (index, SNI) in step 3
    [string]$Exe,              # override path to bosphorus.exe
    [string[]]$ExtraIndex = @() # extra grid indices to include in step 3
)

$ErrorActionPreference = 'Stop'
$inv = [System.Globalization.CultureInfo]::InvariantCulture
$script:engineProc = $null

# Self-contained cleanup trap, armed for the whole script. No variable
# indirection (PowerShell hoists `trap` above the first statement, so anything
# it references must already be safe to touch).
trap {
    Write-Host ("`nERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)") -ForegroundColor Red
    if ($script:engineProc -and -not $script:engineProc.HasExited) {
        Stop-Process -Id $script:engineProc.Id -Force -ErrorAction SilentlyContinue
    }
    break
}

# Script directory / repo root, resilient to how the script was launched
# (`.\scripts\measure-speed.ps1`, `powershell -File ...`, or from repo root).
$scriptDir = $PSScriptRoot
if ((-not $scriptDir) -and $MyInvocation.MyCommand.Path) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ((-not $scriptDir) -or (-not (Test-Path $scriptDir))) { $scriptDir = (Get-Location).Path }

if ((Split-Path -Leaf $scriptDir) -ieq 'scripts') {
    $repoRoot = Split-Path -Parent $scriptDir
} else {
    $repoRoot = $scriptDir     # assume launched from the repo root
}
if ((-not $repoRoot) -or (-not (Test-Path $repoRoot))) { $repoRoot = $scriptDir }

# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Exe {
    if ($Exe) {
        if (Test-Path $Exe) { return (Resolve-Path $Exe).Path }
        Fail "-Exe '$Exe' not found"
    }
    foreach ($p in @("$repoRoot\target\release\bosphorus.exe", "$repoRoot\target\debug\bosphorus.exe")) {
        if (Test-Path $p) { return $p }
    }
    Fail "bosphorus.exe not found under $repoRoot\target\{release,debug} - run: cargo build --release"
}

function Get-Median([double[]]$v) {
    if (-not $v -or $v.Count -eq 0) { return $null }
    $s = @($v | Sort-Object)
    $n = $s.Count
    if ($n % 2) { return $s[[int](($n - 1) / 2)] }
    return ($s[$n / 2 - 1] + $s[$n / 2]) / 2
}

function Ms([double]$sec) { return [math]::Round($sec * 1000, 1) }

# --- reconstruct Strategy::describe() from a profile JSON strategy object --- #

function Get-DesyncName($d) {
    if ($null -eq $d) { return $null }
    if ($d -is [string]) { return $d }
    return ($d.PSObject.Properties | Select-Object -First 1).Name
}

function Get-AnchorLabel($a) {
    if ($a -is [string]) {
        switch ($a) {
            'TlsRecordStart' { return 'tls' }
            'SniStart'       { return 'sni' }
            'SniMiddle'      { return 'sni-mid' }
            default          { return $a }
        }
    }
    $p = $a.PSObject.Properties | Select-Object -First 1
    if ($p.Name -eq 'AbsoluteOffset') { return [string]$p.Value }
    return $p.Name
}

function Get-Describe($st) {
    $s = ''
    if ($st.fake) {
        $dn = Get-DesyncName $st.fake.desync
        if ($dn -eq 'OverlapDisorder') {
            $seqovl = $st.fake.desync.OverlapDisorder.seqovl
            $s += "overlap($seqovl)"
        } else {
            $lbl = switch ($dn) {
                'WrongSeq'        { 'wrong-seq' }
                'WrongChecksum'   { 'wrong-cksum' }
                'TtlLimited'      { 'ttl' }
                'SeqPlusTtl'      { 'seq+ttl' }
                'ChecksumPlusTtl' { 'cksum+ttl' }
                default           { $dn }
            }
            $s += "fake($lbl)"
            if ($st.fake.repeats -gt 1) { $s += "x$($st.fake.repeats)" }
            if ($st.fake.payload -eq 'AggressiveClientHello') { $s += '+big' }
        }
    }
    if ($st.fragment) {
        if ($s) { $s += '+' }
        $labels = @($st.fragment.anchors | ForEach-Object { Get-AnchorLabel $_ })
        $s += 'frag@' + ($labels -join ',')
        if ($st.fragment.reverse) { $s += '(rev)' }
    }
    if ($null -ne $st.tls_pad) {
        if ($s) { $s += '+' }
        $s += "pad($($st.tls_pad))"
    }
    if ($st.order -eq 'RealThenFake') { $s += '[real-first]' }
    if (-not $s) { $s = 'passthrough' }
    return $s
}

function Start-Engine([string[]]$engArgs, [string]$outFile, [string]$errFile) {
    $script:engineProc = Start-Process -FilePath $exe -ArgumentList $engArgs -PassThru `
        -NoNewWindow -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    return $script:engineProc
}

function Stop-EngineHard($p) {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400
    }
    $script:engineProc = $null
}

function Invoke-CurlAppconnect([string]$sni) {
    $w = '%{time_appconnect} %{time_total} %{http_code}'
    $line = & curl.exe -sk -4 -o NUL --connect-timeout 10 --max-time 12 -w $w "https://$sni/" 2>$null
    if (-not $line) { return $null }
    $parts = ($line.Trim() -split '\s+')
    if ($parts.Count -lt 1) { return $null }
    $ac = 0.0
    [void][double]::TryParse($parts[0], [Globalization.NumberStyles]::Float, $inv, [ref]$ac)
    return $ac
}

# --------------------------------------------------------------------------- #
#  preflight
# --------------------------------------------------------------------------- #

if (-not (Test-Admin)) { Fail "run this from an ELEVATED (Administrator) PowerShell" }
$exe = Resolve-Exe
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Fail "curl.exe not on PATH" }

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot "measure-out\$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host ""
Write-Host "Bosphorus speed measurement" -ForegroundColor Cyan
Write-Host "  exe    : $exe"
Write-Host "  output : $outDir"
Write-Host ""

$svc = Get-Service -Name Bosphorus -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "WARNING: the Bosphorus SERVICE is Running. It captures the same traffic and" -ForegroundColor Yellow
    Write-Host "         will confound every measurement below. Stop it first (elevated):" -ForegroundColor Yellow
    Write-Host "             Stop-Service Bosphorus" -ForegroundColor Yellow
    Write-Host "         then re-run this script. Press Ctrl+C to abort, or Enter to continue anyway."
    Read-Host " " | Out-Null
}

# --------------------------------------------------------------------------- #
#  STEP 1  -  freeze the current profile
# --------------------------------------------------------------------------- #

Write-Host "[1/4] reading discovery profile ..." -ForegroundColor Green

$profileDirs = @(
    (Join-Path $env:LOCALAPPDATA 'Bosphorus\profiles'),
    (Join-Path $env:ProgramData  'Bosphorus\profiles')
)
$profileFiles = @()
foreach ($d in $profileDirs) {
    if (Test-Path $d) {
        $profileFiles += Get-ChildItem -Path $d -Filter '*.json' -File -ErrorAction SilentlyContinue
    }
}

$step1 = New-Object System.Collections.Generic.List[string]
$step1.Add("profile directories checked:")
foreach ($d in $profileDirs) { $step1.Add("  $d  (exists: $([bool](Test-Path $d)))") }
$step1.Add("")

$discordActive = @()   # [pscustomobject] key / describe / successes / trials / quality
$promotedIdx   = $null
$chosen        = $null

if (-not $profileFiles -or $profileFiles.Count -eq 0) {
    $step1.Add("NO PROFILE FILES FOUND. Run  bosphorus --engine  on this network first (a few minutes,")
    $step1.Add("with Discord open) so it learns, then re-run this script.")
} else {
    $step1.Add("profile files (newest first):")
    foreach ($f in ($profileFiles | Sort-Object LastWriteTime -Descending)) {
        $step1.Add(("  {0,-20}  {1}  {2}" -f $f.Name, $f.LastWriteTime, $f.FullName))
    }
    $chosen = $profileFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $step1.Add("")
    $step1.Add("USING: $($chosen.FullName)  (most recently written)")

    $json = Get-Content -Raw -Path $chosen.FullName | ConvertFrom-Json
    $step1.Add("  net_key        : $($json.net_key)")
    $step1.Add("  profile version: $($json.version)")
    $step1.Add("  grid_signature : $($json.grid_signature)")
    $step1.Add("  total targets  : $(@($json.targets).Count)")
    $step1.Add("")
    $step1.Add("discord* targets:")
    $step1.Add(("  {0,-34} {1,-9} {2,-26} {3,-11} {4}" -f 'SNI', 'phase', 'active strategy', 'succ/trials', 'quality(retxOK/slow, minLat)'))
    $step1.Add("  " + ('-' * 108))

    $dt = @($json.targets | Where-Object { $_.key -match 'discord' })
    if ($dt.Count -eq 0) { $step1.Add("  (none - this network's profile has no discord SNI yet)") }

    foreach ($t in ($dt | Sort-Object key)) {
        $desc = '-'
        $st   = '-'
        $q    = '-'
        if ($null -ne $t.active) {
            $match = @($t.scores | Where-Object { $_ })
            # Active targets are compacted to just the promoted score; if more than
            # one is present, prefer the one with the most successes.
            $sc = $match | Sort-Object { $_.successes } -Descending | Select-Object -First 1
            if ($sc) {
                $desc = Get-Describe $sc.strategy
                $st   = "$($sc.successes)/$($sc.trials)"
                if ($sc.quality) {
                    $ml = if ($null -ne $sc.quality.min_latency) {
                        $s2 = [double]$sc.quality.min_latency.secs
                        $n2 = [double]$sc.quality.min_latency.nanos
                        ("{0}ms" -f [math]::Round(($s2 * 1000 + $n2 / 1e6), 0))
                    } else { '-' }
                    $q = "retxOK=$($sc.quality.retx_free_successes) slow=$($sc.quality.slow_successes) min=$ml"
                }
            }
        }
        $step1.Add(("  {0,-34} {1,-9} {2,-26} {3,-11} {4}" -f (
            $t.key, $t.phase, $desc, $st, $q)))

        if ($t.phase -eq 'Active' -and $null -ne $t.active) {
            $discordActive += [pscustomobject]@{ key = $t.key; describe = $desc }
        }
    }
}

# resolve the promoted strategy's grid index from `--strategy list`
$listRaw = & $exe --engine --strategy list --enable-overlap 2>&1
$gridMap = @{}
$gridLen = 0
foreach ($l in $listRaw) {
    $s = [string]$l
    if ($s -match '^\s*\[\s*(\d+)\]\s+(.+?)\s*$') {
        $gridMap[$matches[2]] = [int]$matches[1]
        if ([int]$matches[1] + 1 -gt $gridLen) { $gridLen = [int]$matches[1] + 1 }
    }
}
$step1.Add("")
$step1.Add("grid size (--enable-overlap): $gridLen strategies")

$promotedDescr = @($discordActive | Select-Object -ExpandProperty describe -Unique)
$step1.Add("")
$step1.Add("promoted strategy(s) on Active discord targets -> grid index:")
$promotedIndices = @()
foreach ($d in $promotedDescr) {
    if ($gridMap.ContainsKey($d)) {
        $step1.Add("  '$d'  -> grid:$($gridMap[$d])")
        $promotedIndices += $gridMap[$d]
    } else {
        $step1.Add("  '$d'  -> (no exact match in the grid list; will only test the representative set)")
    }
}
$promotedIndices = @($promotedIndices | Select-Object -Unique)

($step1 -join "`r`n") | Set-Content -Path (Join-Path $outDir '1-profile.txt') -Encoding utf8
Write-Host ($step1 -join "`r`n")
Write-Host ""

# --------------------------------------------------------------------------- #
#  STEP 2  -  auto-discovery window + retransmit smoking gun
# --------------------------------------------------------------------------- #

Write-Host "[2/4] auto-discovery window ($Secs s) with verbose tracing." -ForegroundColor Green
Write-Host "      CLOSE the Discord desktop app completely now." -ForegroundColor Yellow
Read-Host "      press Enter when Discord is closed" | Out-Null

$env:RUST_LOG = 'bosphorus::strategy=debug,bosphorus::discovery=debug,bosphorus::conntrack=info,bosphorus::net=info'
$e2out = Join-Path $outDir '2-engine.out.log'
$e2err = Join-Path $outDir '2-engine.err.log'
$p = Start-Engine @('--engine', '--secs', "$Secs") $e2out $e2err
Start-Sleep -Seconds 3
Write-Host ""
Write-Host "  >> OPEN DISCORD NOW - log in / let it fully load <<" -ForegroundColor Cyan -BackgroundColor DarkBlue
Write-Host ""
try { $p | Wait-Process -Timeout ($Secs + 25) } catch { Stop-EngineHard $p }
Stop-EngineHard $p
$env:RUST_LOG = $null
Write-Host "  >> you can close Discord <<" -ForegroundColor Cyan
Write-Host ""

$log = @()
if (Test-Path $e2err) { $log += Get-Content -Path $e2err }
if (Test-Path $e2out) { $log += Get-Content -Path $e2out }

# ip -> sni map from `flow classified` lines
$ipToSni = @{}
foreach ($m in ($log | Select-String -Pattern 'flow classified' -SimpleMatch)) {
    $t = $m.Line; $sni = $null; $ip = $null
    if ($t -match 'server="([^"]*)"')            { $sni = $matches[1] }
    if ($t -match 'server_ip=([0-9a-fA-F:.]+)')  { $ip  = $matches[1] }
    if ($ip -and $sni -and $sni -ne '?' -and -not $ipToSni.ContainsKey($ip)) { $ipToSni[$ip] = $sni }
}

$retxLines = @($log | Select-String -Pattern 'ClientHello retransmit after strategy already applied' -SimpleMatch)
$retxByServer = @{}
foreach ($m in $retxLines) {
    $ip = if ($m.Line -match 'server_ip=([0-9a-fA-F:.]+)') { $matches[1] } else { '?' }
    $name = if ($ipToSni.ContainsKey($ip)) { $ipToSni[$ip] } else { $ip }
    if (-not $retxByServer.ContainsKey($name)) { $retxByServer[$name] = 0 }
    $retxByServer[$name]++
}

$classified   = @($log | Select-String -Pattern 'flow classified' -SimpleMatch)
$successLines  = @($classified | Where-Object { $_.Line -match 'outcome=Success' })
$blackholeTO   = @($classified | Where-Object { $_.Line -match 'outcome=Blackhole' -and $_.Line -match 'via="?timeout' })
$dpiResets     = @($classified | Where-Object { $_.Line -match 'outcome=DpiReset' })
$discordCls    = @($classified | Where-Object { $_.Line -match 'discord' })
$discoveryEv   = @($log | Select-String -Pattern 'discovery update|discovery progress|Promoted|Demoted|Blocked|NextCandidate|EXHAUSTED')
$discordDiscov = @($discoveryEv | Where-Object { $_.Line -match 'discord' })

# the discovery summary the engine prints on exit (stdout)
$summaryBlock = @()
if (Test-Path $e2out) {
    $lines = Get-Content -Path $e2out
    $i = ($lines | Select-String -Pattern 'discovery summary|keşif özeti' | Select-Object -First 1)
    if ($i) { $summaryBlock = $lines[($i.LineNumber - 1)..([math]::Min($lines.Count - 1, $i.LineNumber + 40))] }
}

# --------------------------------------------------------------------------- #
#  STEP 3  -  grid index comparison (curl time_appconnect)
# --------------------------------------------------------------------------- #

Write-Host "[3/4] grid strategy comparison via curl (TLS handshake time)." -ForegroundColor Green
if ($discordActive.Count -eq 0) {
    Write-Host "      no Active discord SNI in the profile - falling back to discord.com" -ForegroundColor Yellow
    $discordActive = @([pscustomobject]@{ key = 'discord.com'; describe = '(unknown)' })
}
$targetSnis = @($discordActive | Select-Object -ExpandProperty key -Unique)
Write-Host ("      targets : {0}" -f ($targetSnis -join ', '))
Write-Host "      keep other :443 traffic (browser etc.) closed if you can." -ForegroundColor Yellow
Write-Host "      this sweep takes a few minutes (no Discord interaction needed here)."
Read-Host "      press Enter to start" | Out-Null

$idxSet = @()
$idxSet += $promotedIndices
foreach ($pi in $promotedIndices) { $idxSet += ($pi - 1); $idxSet += ($pi + 1) }
$idxSet += 0, 1, 2, 5, 142, 154, 160
foreach ($x in $ExtraIndex) { $idxSet += [int]$x }
$idxSet = @($idxSet | Where-Object { $_ -ge 0 -and $_ -lt $gridLen } | Select-Object -Unique | Sort-Object)

$rows = New-Object System.Collections.Generic.List[object]

function Measure-Set([string]$label, [object]$idx) {
    foreach ($sni in $targetSnis) {
        $vals = @()
        $fail = 0
        for ($k = 1; $k -le $CurlIterations; $k++) {
            $ac = Invoke-CurlAppconnect $sni
            if ($null -eq $ac -or $ac -le 0) { $fail++ } else { $vals += [double]$ac }
            # bail early if this (index,SNI) is clearly broken
            if ($fail -ge 2 -and $vals.Count -eq 0) { break }
            Start-Sleep -Milliseconds 300
        }
        $med = Get-Median $vals
        $rows.Add([pscustomobject]@{
            index    = $label
            describe = if ($null -ne $idx -and $gridMap.Values -contains $idx) {
                           ($gridMap.GetEnumerator() | Where-Object { $_.Value -eq $idx } | Select-Object -First 1).Key
                       } else { '' }
            sni      = $sni
            n_ok     = $vals.Count
            n_fail   = $fail
            med_ms   = if ($null -ne $med) { Ms $med } else { '' }
            min_ms   = if ($vals.Count) { Ms ($vals | Measure-Object -Minimum).Minimum } else { '' }
            max_ms   = if ($vals.Count) { Ms ($vals | Measure-Object -Maximum).Maximum } else { '' }
        })
    }
}

Write-Host "  - baseline (no engine running) ..."
Measure-Set 'baseline' $null

foreach ($idx in $idxSet) {
    $tag = if ($promotedIndices -contains $idx) { "grid:$idx  <== PROMOTED" } else { "grid:$idx" }
    Write-Host "  - $tag ..."
    $gout = Join-Path $outDir "3-engine-grid-$idx.log"
    $p = Start-Engine @('--engine', '--strategy', "grid:$idx", '--enable-overlap', '--secs', '90') $gout "$gout.err"
    Start-Sleep -Seconds 3
    Measure-Set "grid:$idx" $idx
    Stop-EngineHard $p
    Start-Sleep -Seconds 1
}

$rows | Export-Csv -Path (Join-Path $outDir '3-grid.csv') -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------- #
#  STEP 4  -  --observe burst width
# --------------------------------------------------------------------------- #

Write-Host ""
Write-Host "[4/4] --observe burst width ($ObserveSecs s)." -ForegroundColor Green
Write-Host "      CLOSE Discord again." -ForegroundColor Yellow
Read-Host "      press Enter when Discord is closed" | Out-Null

$obsFile = Join-Path $outDir '4-observe.txt'
$p = Start-Process -FilePath $exe -ArgumentList @('--observe', '--secs', "$ObserveSecs") -PassThru `
     -NoNewWindow -RedirectStandardOutput $obsFile -RedirectStandardError "$obsFile.err"
$script:engineProc = $p
Start-Sleep -Seconds 2
Write-Host ""
Write-Host "  >> OPEN DISCORD NOW - log in <<" -ForegroundColor Cyan -BackgroundColor DarkBlue
Write-Host ""
try { $p | Wait-Process -Timeout ($ObserveSecs + 25) } catch { Stop-EngineHard $p }
Stop-EngineHard $p
Write-Host "  >> you can close Discord <<" -ForegroundColor Cyan

$obs = @()
if (Test-Path $obsFile) { $obs = Get-Content -Path $obsFile }
$obsDiscordRows = @($obs | Where-Object { $_ -match 'discord' })
$obsDistinct    = @($obsDiscordRows | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ } | Select-Object -Unique)
$obsRstRows     = @($obsDiscordRows | Where-Object { $_ -match '\bDpiReset\b' })

# --------------------------------------------------------------------------- #
#  SUMMARY
# --------------------------------------------------------------------------- #

$S = New-Object System.Collections.Generic.List[string]
$S.Add('================ MEASURE-SPEED SUMMARY (paste this whole block back) ================')
$S.Add("timestamp : $stamp")
$S.Add("exe       : $exe")
$S.Add("outdir    : $outDir")
$S.Add('')
$S.Add('--- [1] discord targets in the frozen profile ---')
if ($chosen) { $S.Add("profile: $($chosen.FullName)  net_key=$($json.net_key)") }
$dt = @()
if ($json) { $dt = @($json.targets | Where-Object { $_.key -match 'discord' } | Sort-Object key) }
if ($dt.Count -eq 0) {
    $S.Add('  (no discord targets learned on this network yet)')
} else {
    $S.Add(("  {0,-34} {1,-9} {2,-24} {3,-9} {4}" -f 'SNI','phase','strategy','s/t','quality'))
    foreach ($t in $dt) {
        $desc='-'; $st='-'; $q='-'
        if ($null -ne $t.active) {
            $sc = @($t.scores) | Sort-Object { $_.successes } -Descending | Select-Object -First 1
            if ($sc) {
                $desc = Get-Describe $sc.strategy
                $st = "$($sc.successes)/$($sc.trials)"
                if ($sc.quality) { $q = "retxOK=$($sc.quality.retx_free_successes) slow=$($sc.quality.slow_successes)" }
            }
        }
        $S.Add(("  {0,-34} {1,-9} {2,-24} {3,-9} {4}" -f $t.key,$t.phase,$desc,$st,$q))
    }
}
$S.Add('')
$S.Add('--- [2] retransmit smoking gun (auto-discovery window) ---')
$S.Add("window                 : $Secs s")
$S.Add("flows classified       : $($classified.Count)   (Success=$($successLines.Count)  DpiReset=$($dpiResets.Count)  Blackhole/timeout=$($blackholeTO.Count))")
$S.Add("'ClientHello retransmit after strategy applied' total : $($retxLines.Count)")
if ($retxByServer.Count -gt 0) {
    $S.Add("  per server (RTO paid on an already-desynced ClientHello):")
    foreach ($k in ($retxByServer.Keys | Sort-Object { -$retxByServer[$_] })) {
        $S.Add(("    {0,-40} {1}" -f $k, $retxByServer[$k]))
    }
} else {
    $S.Add("  (none seen - the applied strategies did NOT force a ClientHello retransmit)")
}
$S.Add("discord flow-classified lines : $($discordCls.Count)")
foreach ($l in ($discordCls | Select-Object -First 25)) { $S.Add("    $($l.Line.Trim())") }
$S.Add("discord discovery events      : $($discordDiscov.Count)")
foreach ($l in ($discordDiscov | Select-Object -First 25)) { $S.Add("    $($l.Line.Trim())") }
if ($summaryBlock.Count -gt 0) {
    $S.Add('  engine discovery summary on exit:')
    foreach ($l in $summaryBlock) { $S.Add("    $l") }
}
$S.Add('')
$S.Add('--- [3] grid strategy comparison (curl time_appconnect, ms) ---')
$S.Add("iterations per (index,SNI): $CurlIterations")
$S.Add("PROMOTED index(es)        : $((@($promotedIndices) -join ', '))")
$S.Add(("  {0,-16} {1,-24} {2,-22} {3,5} {4,5} {5,8} {6,8} {7,8}" -f 'index','strategy','sni','ok','fail','med_ms','min_ms','max_ms'))
$S.Add('  ' + ('-' * 104))
foreach ($r in $rows) {
    $S.Add(("  {0,-16} {1,-24} {2,-22} {3,5} {4,5} {5,8} {6,8} {7,8}" -f `
        $r.index, $r.describe, $r.sni, $r.n_ok, $r.n_fail, $r.med_ms, $r.min_ms, $r.max_ms))
}
$S.Add('')
$S.Add('--- [4] --observe burst width ---')
$S.Add("window                 : $ObserveSecs s")
$S.Add("distinct discord SNIs  : $($obsDistinct.Count)")
foreach ($d in $obsDistinct) { $S.Add("    $d") }
$S.Add("discord rows w/ DpiReset: $($obsRstRows.Count)")
$S.Add('  raw discord rows from the --observe table:')
foreach ($l in $obsDiscordRows) { $S.Add("    $l") }
$S.Add('')
$S.Add('--- interpretation hint ---')
$S.Add('  [2] retransmit total high on discord servers  -> promoted strategy pays an RTO   (fix: promote-gate A)')
$S.Add('  [2] ~zero retransmit, [4] many distinct SNIs, [2] discovery events for discord  -> "still learning" cold burst (fix: persistence + ISP seeding)')
$S.Add('  [3] PROMOTED index median_ms >> some other index median_ms                       -> a faster candidate exists (confirms A)')
$S.Add('  [3] PROMOTED median ~= baseline and other indices                               -> strategy is fine; 15s is elsewhere')
$S.Add('===================================================================================')

$txt = ($S -join "`r`n")
$txt | Set-Content -Path (Join-Path $outDir 'SUMMARY.txt') -Encoding utf8
Write-Host ""
Write-Host $txt
Write-Host ""
Write-Host "saved: $(Join-Path $outDir 'SUMMARY.txt')" -ForegroundColor Green
