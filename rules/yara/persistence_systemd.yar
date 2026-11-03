/*
  Hornwork 自研 YARA 规则：systemd 持久化单元
  检测指向 /tmp、/dev/shm 等临时目录的 ExecStart 单元文件。
*/
rule persistence_systemd
{
    meta:
        description = "Systemd unit persisting payload from temporary directory"
        attack = "T1543.002"
        severity = 80
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $u1 = "[Unit]" ascii
        $u2 = "ExecStart=" ascii
        $u3 = "WantedBy=" ascii
        $u4 = "Restart=always" ascii
        $t1 = "/tmp/" ascii
        $t2 = "/dev/shm/" ascii
        $t3 = "/var/tmp/" ascii

    condition:
        filesize < 1MB and 2 of ($u*) and 1 of ($t*)
}
