#!/system/bin/sh
# 由 rootd 以 uid=0 执行：late-load KernelSU 模块（LKM 模式）。
#
# 只做 late-load。早前版本会先 nohup 起 ksud 守护进程再加载模块，
# 实测该顺序会触发内核 panic 重启；这里只保留已验证可用的最小路径。
# 模块加载后 SELinux 会被 KSU 拉回 Enforcing，本 shell 可能随即失效，
# 所以写日志的动作都放在 late-load 前后各自独立的步骤里。

KSUD=/data/local/tmp/ksud
KMI=android15-6.6
LOG=/data/local/tmp/cvehome/ksu_step.log

echo "[step] begin uid=$(id -u) enf=$(getenforce)" > "$LOG"

chmod 755 "$KSUD" 2>/dev/null
setenforce 0 2>/dev/null
echo "[step] enf=$(getenforce)" >> "$LOG"
sync

if grep -qi kernelsu /proc/modules 2>/dev/null; then
    echo "[step] module_already_live" >> "$LOG"
else
    "$KSUD" late-load --kmi "$KMI" >> "$LOG" 2>&1
    echo "[step] late_rc=$?" >> "$LOG"
    sleep 2
    if ! grep -qi kernelsu /proc/modules 2>/dev/null; then
        "$KSUD" late-load >> "$LOG" 2>&1
        echo "[step] late_rc2=$?" >> "$LOG"
    fi
fi

if grep -qi kernelsu /proc/modules 2>/dev/null; then
    echo "[step] module=live" >> "$LOG"
else
    echo "[step] module=absent" >> "$LOG"
fi

exit 0
