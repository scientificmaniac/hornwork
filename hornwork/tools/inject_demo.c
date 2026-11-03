/*
 * Hornwork 内存注入演示
 *
 * 原理（x86_64）：
 *   PTRACE_ATTACH → PTRACE_GETREGS 取 RIP → PTRACE_PEEKDATA 备份原指令字
 *   → PTRACE_POKEDATA 把目标地址首字节改为 0x90(NOP) 或 0xCC(INT3)
 *   → PTRACE_SETREGS → PTRACE_DETACH。--restore 时按状态文件回写原始指令字。
 *
 * 安全约束：
 *   - 只允许操作与调用者 **同 uid** 的目标进程（getuid() == /proc/<pid> 所有者）；
 *   - 拒绝 PID 1、拒绝自身、拒绝 setuid 调用；
 *   - 只改 1 个字节的代码（NOP/INT3），不分配内存、不注入 shellcode；
 *   - 状态文件记录 pid/addr/orig 原字，用于 --restore 回写，默认 0600。
 *
 * 构建：gcc -O2 -Wall -Wextra -o inject_demo hornwork/tools/inject_demo.c
 * 用法：
 *   sudo ./inject_demo --pid 1234                 # 默认把 RIP 处首字节改为 NOP
 *   sudo ./inject_demo --pid 1234 --byte cc       # 改为 INT3（进程会收到 SIGTRAP）
 *   sudo ./inject_demo --pid 1234 --addr 0x4011a0 --byte nop
 *   sudo ./inject_demo --pid 1234 --restore       # 回写原始指令字
 *   ./inject_demo --pid 1234 --state /tmp/x.state # 指定状态文件
 * 说明：需要内核允许 ptrace（Ubuntu 默认 yama ptrace_scope=1，同 uid 的父进程可 attach；
 *       sudo 运行或对同 uid 非子进程 attach 需确认 ptrace_scope 配置）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STATE_MAGIC "hornwork-inject-demo-v1"
#define STATE_MAX 4096

static const char *prog = "inject_demo";

static void ts_now(char *buf, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%S%z", &tm);
}

static void logf_(const char *level, const char *fmt, ...)
{
    char ts[64];
    va_list ap;
    ts_now(ts, sizeof(ts));
    fprintf(stderr, "[%s] %-5s %s: ", ts, level, prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#define LOGI(...) logf_("INFO", __VA_ARGS__)
#define LOGW(...) logf_("WARN", __VA_ARGS__)
#define LOGE(...) logf_("ERROR", __VA_ARGS__)

static void usage(int code)
{
    printf(
        "用法: %s --pid PID [选项]\n"
        "\n"
        "选项:\n"
        "  --pid PID         目标进程号（必须与调用者同 uid）\n"
        "  --addr HEX        注入地址（默认取 attach 时 RIP；支持 0x 前缀）\n"
        "  --byte nop|cc     nop=0x90（默认），cc=0xCC(INT3)\n"
        "  --restore         按状态文件回写注入前的原始指令字\n"
        "  --state PATH      状态文件路径（默认 /tmp/inject_demo-<pid>.state）\n"
        "  -h, --help        显示帮助\n"
        "\n"
        "示例:\n"
        "  sudo %s --pid 1234\n"
        "  sudo %s --pid 1234 --restore\n",
        prog, prog, prog);
    exit(code);
}

static int parse_pid(const char *s, pid_t *out)
{
    char *end = NULL;
    long v;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v <= 1 || v > 4194304) {
        return -1;
    }
    *out = (pid_t)v;
    return 0;
}

static int parse_hex_addr(const char *s, uintptr_t *out)
{
    char *end = NULL;
    unsigned long long v;
    errno = 0;
    v = strtoull(s, &end, 0); /* 0 前缀自动识别 0x */
    if (errno || !end || *end != '\0') {
        return -1;
    }
    *out = (uintptr_t)v;
    return 0;
}

/* 校验目标进程 uid 与调用者一致；返回 0 表示允许，-1 拒绝（已打印原因） */
static int check_same_uid(pid_t pid)
{
    char path[64];
    struct stat st;

    if (getuid() != geteuid()) {
        LOGE("检测到 setuid 场景（ruid=%u euid=%u），为安全起见拒绝执行",
             (unsigned)getuid(), (unsigned)geteuid());
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/%d", (int)pid);
    if (stat(path, &st) != 0) {
        LOGE("目标进程不存在或无权访问 %s：%s", path, strerror(errno));
        return -1;
    }
    if (st.st_uid != getuid()) {
        LOGE("拒绝：目标 pid=%d 属于 uid=%u，调用者 uid=%u（只允许同 uid 目标进程）",
             (int)pid, (unsigned)st.st_uid, (unsigned)getuid());
        return -1;
    }
    return 0;
}

static void default_state_path(pid_t pid, char *buf, size_t n)
{
    const char *env = getenv("INJECT_DEMO_STATE");
    if (env != NULL && *env != '\0') {
        snprintf(buf, n, "%s", env);
        return;
    }
    snprintf(buf, n, "/tmp/inject_demo-%d.state", (int)pid);
}

static int write_state(const char *path, pid_t pid, uintptr_t addr,
                       unsigned long orig, unsigned char byte)
{
    char tmp[STATE_MAX];
    int fd;
    mode_t old;
    ssize_t n;
    int len = snprintf(tmp, sizeof(tmp),
                       "%s\npid=%d\naddr=0x%llx\norig=0x%llx\nbyte=0x%02x\nuid=%u\n",
                       STATE_MAGIC, (int)pid, (unsigned long long)addr,
                       (unsigned long long)orig, (unsigned)byte, (unsigned)getuid());
    if (len <= 0 || (size_t)len >= sizeof(tmp)) {
        return -1;
    }
    old = umask(0077);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    umask(old);
    if (fd < 0) {
        return -1;
    }
    n = write(fd, tmp, (size_t)len);
    if (n != len) {
        close(fd);
        return -1;
    }
    if (fsync(fd) != 0) {
        /* 状态文件落盘失败不致命，但给出告警 */
        LOGW("状态文件 fsync 失败：%s", strerror(errno));
    }
    close(fd);
    return 0;
}

struct state {
    pid_t pid;
    uintptr_t addr;
    unsigned long orig;
    unsigned char byte;
    unsigned uid;
};

static int read_state(const char *path, struct state *st)
{
    char buf[STATE_MAX];
    char *line;
    int fd;
    ssize_t n;
    int seen_magic = 0;

    memset(st, 0, sizeof(*st));
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOGE("读取状态文件失败 %s：%s", path, strerror(errno));
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        LOGE("状态文件为空或不可读：%s", path);
        return -1;
    }
    buf[n] = '\0';
    line = strtok(buf, "\n");
    if (line == NULL) {
        return -1;
    }
    seen_magic = (strcmp(line, STATE_MAGIC) == 0);
    while ((line = strtok(NULL, "\n")) != NULL) {
        int pid_v = 0;
        unsigned uid_v = 0;
        unsigned byte_v = 0;
        unsigned long long addr_v = 0;
        unsigned long long orig_v = 0;
        if (sscanf(line, "pid=%d", &pid_v) == 1) {
            st->pid = (pid_t)pid_v;
            continue;
        }
        if (sscanf(line, "addr=%llx", &addr_v) == 1) {
            st->addr = (uintptr_t)addr_v;
            continue;
        }
        if (sscanf(line, "orig=%llx", &orig_v) == 1) {
            st->orig = (unsigned long)orig_v;
            continue;
        }
        if (sscanf(line, "byte=%x", &byte_v) == 1) {
            st->byte = (unsigned char)(byte_v & 0xFF);
            continue;
        }
        if (sscanf(line, "uid=%u", &uid_v) == 1) {
            st->uid = uid_v;
            continue;
        }
    }
    if (!seen_magic) {
        LOGE("状态文件格式不匹配（缺少 magic）：%s", path);
        return -1;
    }
    return 0;
}

static int ptrace_attach(pid_t pid, int *status)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        LOGE("PTRACE_ATTACH 失败 pid=%d：%s", (int)pid, strerror(errno));
        if (errno == EPERM) {
            LOGE("提示：检查 kernel.yama.ptrace_scope（sudo sysctl kernel.yama.ptrace_scope=0 仅演示机可临时放开）");
        }
        return -1;
    }
    if (waitpid(pid, status, 0) != pid || !WIFSTOPPED(*status)) {
        LOGE("等待目标进程停止失败 pid=%d", (int)pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    return 0;
}

static int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0) {
        LOGE("PTRACE_DETACH 失败 pid=%d：%s", (int)pid, strerror(errno));
        return -1;
    }
    return 0;
}

static int do_inject(pid_t pid, int use_addr, uintptr_t want_addr,
                     unsigned char byte, const char *state_path)
{
    struct user_regs_struct regs;
    uintptr_t addr;
    unsigned long orig = 0;
    unsigned long patched = 0;
    int status = 0;

    if (ptrace_attach(pid, &status) != 0) {
        return -1;
    }
    memset(&regs, 0, sizeof(regs));
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        LOGE("PTRACE_GETREGS 失败：%s", strerror(errno));
        ptrace_detach(pid);
        return -1;
    }
#if defined(__x86_64__)
    addr = use_addr ? want_addr : (uintptr_t)regs.rip;
#elif defined(__aarch64__)
    addr = use_addr ? want_addr : (uintptr_t)regs.pc;
#else
    addr = want_addr;
#endif
    if (addr == 0) {
        LOGE("注入地址为 0，请用 --addr 指定");
        ptrace_detach(pid);
        return -1;
    }

    errno = 0;
    orig = (unsigned long)ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (orig == (unsigned long)-1 && errno != 0) {
        LOGE("PTRACE_PEEKDATA 读取地址 0x%llx 失败：%s",
             (unsigned long long)addr, strerror(errno));
        ptrace_detach(pid);
        return -1;
    }
    patched = (orig & ~0xFFUL) | (unsigned long)byte;

    LOGI("已 attach pid=%d，RIP=0x%llx，注入地址=0x%llx",
         (int)pid, (unsigned long long)(uintptr_t)regs.rip, (unsigned long long)addr);
    LOGI("备份原指令字：0x%llx（首字节 0x%02x）", (unsigned long long)orig, (unsigned)(orig & 0xFF));
    LOGI("写入新指令字：0x%llx（首字节 0x%02x = %s）",
         (unsigned long long)patched, (unsigned)byte,
         byte == 0x90 ? "NOP" : (byte == 0xCC ? "INT3" : "自定义"));

    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)patched) != 0) {
        LOGE("PTRACE_POKEDATA 失败：%s", strerror(errno));
        ptrace_detach(pid);
        return -1;
    }

    /* 保持寄存器原值，显式 SETREGS（演示完整注入链路；也便于扩展改 RIP 的场景） */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        LOGE("PTRACE_SETREGS 失败：%s，尝试回滚", strerror(errno));
        ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)orig);
        ptrace_detach(pid);
        return -1;
    }

    if (write_state(state_path, pid, addr, orig, byte) != 0) {
        LOGE("写状态文件失败 %s：%s，回滚注入字节", state_path, strerror(errno));
        ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)orig);
        ptrace_detach(pid);
        return -1;
    }
    LOGI("状态已保存：%s", state_path);

    if (ptrace_detach(pid) != 0) {
        return -1;
    }
    LOGI("注入完成并已 DETACH：pid=%d addr=0x%llx byte=0x%02x",
         (int)pid, (unsigned long long)addr, (unsigned)byte);
    return 0;
}

static int do_restore(pid_t pid, const char *state_path)
{
    struct state st;
    struct user_regs_struct regs;
    unsigned long cur = 0;
    int status = 0;

    if (read_state(state_path, &st) != 0) {
        return -1;
    }
    if (st.pid != pid) {
        LOGE("状态文件记录 pid=%d 与 --pid %d 不一致，拒绝回写", (int)st.pid, (int)pid);
        return -1;
    }
    if (st.uid != getuid()) {
        LOGE("状态文件属于 uid=%u，当前 uid=%u，拒绝回写", st.uid, (unsigned)getuid());
        return -1;
    }
    if (check_same_uid(pid) != 0) {
        return -1;
    }
    if (ptrace_attach(pid, &status) != 0) {
        return -1;
    }
    memset(&regs, 0, sizeof(regs));
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        LOGE("PTRACE_GETREGS 失败：%s", strerror(errno));
        ptrace_detach(pid);
        return -1;
    }
    errno = 0;
    cur = (unsigned long)ptrace(PTRACE_PEEKDATA, pid, (void *)st.addr, NULL);
    if (cur == (unsigned long)-1 && errno != 0) {
        LOGE("PTRACE_PEEKDATA 读取地址 0x%llx 失败：%s",
             (unsigned long long)st.addr, strerror(errno));
        ptrace_detach(pid);
        return -1;
    }
    LOGI("回写前指令字：0x%llx，原始指令字：0x%llx", (unsigned long long)cur,
         (unsigned long long)st.orig);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)st.addr, (void *)st.orig) != 0) {
        LOGE("PTRACE_POKEDATA 回写失败：%s", strerror(errno));
        ptrace_detach(pid);
        return -1;
    }
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        LOGW("PTRACE_SETREGS 失败（不影响已回写的字节）：%s", strerror(errno));
    }
    if (ptrace_detach(pid) != 0) {
        return -1;
    }
    LOGI("回写完成：pid=%d addr=0x%llx 恢复为 0x%llx",
         (int)pid, (unsigned long long)st.addr, (unsigned long long)st.orig);
    if (unlink(state_path) != 0) {
        LOGW("删除状态文件失败 %s：%s", state_path, strerror(errno));
    } else {
        LOGI("已删除状态文件：%s", state_path);
    }
    return 0;
}

int main(int argc, char **argv)
{
    pid_t pid = -1;
    uintptr_t addr = 0;
    int use_addr = 0;
    int restore = 0;
    unsigned char byte = 0x90;
    char state_path[512] = "";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(0);
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            if (parse_pid(argv[++i], &pid) != 0) {
                LOGE("非法 --pid：%s", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--addr") == 0 && i + 1 < argc) {
            if (parse_hex_addr(argv[++i], &addr) != 0) {
                LOGE("非法 --addr：%s", argv[i]);
                return 2;
            }
            use_addr = 1;
        } else if (strcmp(argv[i], "--byte") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "nop") == 0) {
                byte = 0x90;
            } else if (strcmp(v, "cc") == 0 || strcmp(v, "int3") == 0) {
                byte = 0xCC;
            } else {
                int val = (int)strtol(v, NULL, 0);
                if (val < 0 || val > 0xFF) {
                    LOGE("非法 --byte：%s（只支持 nop / cc / 0x00-0xff）", v);
                    return 2;
                }
                byte = (unsigned char)val;
            }
        } else if (strcmp(argv[i], "--restore") == 0) {
            restore = 1;
        } else if (strcmp(argv[i], "--state") == 0 && i + 1 < argc) {
            snprintf(state_path, sizeof(state_path), "%s", argv[++i]);
        } else {
            LOGE("未知参数：%s（用 --help 查看用法）", argv[i]);
            return 2;
        }
    }
    if (pid <= 0) {
        LOGE("必须指定 --pid");
        usage(2);
    }
    if (pid == getpid()) {
        LOGE("拒绝操作自身进程 pid=%d", (int)pid);
        return 1;
    }
    if (check_same_uid(pid) != 0) {
        return 1;
    }
    if (state_path[0] == '\0') {
        default_state_path(pid, state_path, sizeof(state_path));
    }

    LOGI("Hornwork 内存注入演示：pid=%d uid=%u state=%s restore=%d",
         (int)pid, (unsigned)getuid(), state_path, restore);
    if (restore) {
        return do_restore(pid, state_path) == 0 ? 0 : 1;
    }
    if (access(state_path, F_OK) == 0) {
        LOGW("状态文件已存在（可能已注入过）：%s；如需回写请用 --restore", state_path);
    }
    return do_inject(pid, use_addr, addr, byte, state_path) == 0 ? 0 : 1;
}
