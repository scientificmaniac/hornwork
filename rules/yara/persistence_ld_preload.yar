/*
  Hornwork 自研 YARA 规则：ld.so.preload 动态链接器劫持
  两个方向：
  1) 脚本/命令行中出现 /etc/ld.so.preload 或 LD_PRELOAD=；
  2) 目标文件本身就是 ld.so.preload 的内容（短小、含 .so 且指向临时目录）。
*/
rule persistence_ld_preload
{
    meta:
        description = "LD_PRELOAD / ld.so.preload hijacking markers"
        attack = "T1574.006"
        severity = 85
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $p1 = "/etc/ld.so.preload" ascii
        $p2 = "LD_PRELOAD=" ascii
        $p3 = "LD_PRELOAD " ascii
        $p4 = "ld.so.preload" ascii
        $so = ".so" ascii
        $t1 = "/tmp/" ascii
        $t2 = "/dev/shm/" ascii
        $t3 = "/var/tmp/" ascii

    condition:
        filesize < 1MB and
        (
            1 of ($p1, $p2, $p3, $p4)
            or
            (filesize < 4096 and $so and 1 of ($t1, $t2, $t3))
        )
}
