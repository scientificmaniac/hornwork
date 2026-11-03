/*
  Hornwork 自研 YARA 规则：/tmp 等临时目录可执行写入
  检测脚本中"chmod +x /tmp/xxx"或"写入 /tmp 后立即执行"的落盘行为。
*/
rule tmp_exec_drop
{
    meta:
        description = "Executable payload dropped into /tmp, /dev/shm or /var/tmp"
        attack = "T1105"
        severity = 70
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $r1 = /chmod\s+(\+x|[0-7]{3,4})[^\n]{0,80}(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)/ ascii
        $r2 = /(cat|echo|printf)[^\n]{0,120}>\s*\/(tmp|dev\/shm|var\/tmp)\/[^\s]{1,80}/ ascii
        $r3 = /\/tmp\/[^\s"']{1,64}\s*&&\s*(\.\/|bash|sh\s|\/bin\/sh)/ ascii

    condition:
        filesize < 2MB and any of them
}
