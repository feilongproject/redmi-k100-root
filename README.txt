REDMI K100 一键 ROOT 工具包
========================================

适用设备（必须完全匹配，否则不要运行）
----------------------------------------
  机型    REDMI K100 (代号 warsaw / 型号 M786BC)
  系统    HyperOS OS4.0.3.0.XHPCNXM / Android 17
  内核    6.6.118-android15-8-g0908354dac1b-ab16143355-4k

原理
----------------------------------------
  CVE-2026-98260：fs/exec.c 中非 leader 线程 exec 失败时，POSIX CPU timer
  的清理被放在多个可失败操作之后，导致 k_itimer 释放后其 timerqueue 节点
  仍挂在存活任务上，父进程回收时对已释放节点做 rb_erase，形成 UAF 写。

  利用链：触发 UAF -> 受控写 -> 关闭 SELinux -> 伪造 cred -> uid=0
          -> 通过 rootd 以 uid=0 执行 ksud late-load，加载 KernelSU。

  KernelSU 以 LKM（可加载模块）方式运行，只存在于内存，重启即失效。

前置条件
----------------------------------------
  1. Windows 10/11，能运行 PowerShell 5.1 或 7
  2. adb（脚本自动在 PATH、D:\SDKs\Android\platform-tools 等位置查找）
  3. 手机已开启 开发者选项 -> USB 调试，并已授权本机
  4. 建议关闭系统自动更新（升级到 6.6.158+ 后本工具立即失效）

用法
----------------------------------------
  双击    一键ROOT.bat
  命令行  pwsh -NoProfile -ExecutionPolicy Bypass -File root.ps1

  可选参数：
    -CheckOnly   只做环境检查，不推送、不改机
    -SkipKsu     只提权，不加载 KernelSU
    -AdbPath     指定 adb.exe 路径
    -Force       跳过机型/内核校验（危险，不建议）

执行流程
----------------------------------------
  阶段 0  检查设备、机型、内核、bin 文件完整性
  阶段 1  推送 cve98260 / profile.bin / ksud 到 /data/local/tmp
  阶段 2  calibrate-a 求 KASLR slide，calibrate-b 求 page_offset
          （带校验：slide 必须 2MiB 对齐且命中数 >= 64，
            page_offset 必须等于 profile 值，否则自动重试，最多 4 次）
  阶段 3  exploit 注入，轮询 rootd 拿 uid=0（约 20 秒 ~ 5 分钟）
  阶段 4  ksud late-load 加载 KernelSU 模块，校验 /proc/modules
  阶段 5  输出总结

成功判据
----------------------------------------
  提权成功   adb shell "cd /data/local/tmp && ./cve98260 su -c id"
             输出 uid=0(root) gid=0(root)
  KSU 成功   adb shell "grep kernelsu /proc/modules" 有内核模块
             KernelSU 管理器显示「工作中 [越狱模式]」，模式 LKM

已知限制（重要）
----------------------------------------
  · KSU 只完成内核侧加载。ksud 用户态守护进程本脚本不启动：
    实测「先起 ksud 再 late-load」会触发内核 panic 重启，
    因此 ksu_step.sh 只保留已验证安全的 late-load。
    结果是 adb shell 里暂时没有 /system/bin/su，
    提权请用：adb shell "cd /data/local/tmp && ./cve98260 su -c <命令>"

  · 管理器里出现「超级用户」待授权请求时，可在界面上手动授予。
    模块加载后 SELinux 会回到 Enforcing，这是 KernelSU 的正常行为。

  · 临时 root 和 KSU 都只在内存里，重启后需重新运行本脚本。

失败处理
----------------------------------------
  · 内核版本不匹配
      中止是正确的。系统升级后新内核很可能已修复该 CVE，
      本工具对该机失效，请勿用 -Force 强跑（符号偏移不同会 panic）。

  · 未检测到设备 / unauthorized
      开启 USB 调试，手机上点「允许 USB 调试」，重新插拔数据线。

  · 阶段 2 校准连续失败
      多半是刚开机负载太高。等 1~2 分钟、熄屏后再跑；
      持续失败则说明内核已变，profile 需要重新生成。

  · 阶段 3 失败
      重启手机后重跑。重启是唯一干净的清理方式，
      不要 kill /data/local/tmp/cve98260 进程（可能持有内核对象）。

  · 阶段 4 设备断开
      说明 KSU 阶段触发了 panic 重启，属已知风险；
      重启后重跑，或用 -SkipKsu 只取 root。

风险提示
----------------------------------------
  · 本工具改写内核内存，存在 panic / 重启 / 数据丢失风险。
  · 变砖恢复依赖 9008(EDL)，新机型可能需要授权账号，请自行评估。
  · 仅用于你自己的设备。

文件说明
----------------------------------------
  bin/cve98260      exploit 主程序（arm64，静态 PIE）
  bin/profile.bin   308 字节内核偏移表（按本构建 kallsyms 生成）
  bin/ksud          KernelSU 用户态（late-load 用）
  ksu_step.sh       在 rootd 下执行的 KSU 加载脚本
  root.ps1          主逻辑
  一键ROOT.bat      双击入口
  log/              每次运行的日志（run-*.log、exploit-*.out）
