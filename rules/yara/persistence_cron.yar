/*
  Hornwork 自研 YARA 规则：cron 持久化脚本
  检测同时出现"cron 持久化路径/命令"与"下载/执行"特征的脚本文件。
  典型形态：echo '... | bash' >> /etc/cron.d/x && chmod +x ...
*/
rule persistence_cron
{
    meta:
        description = "Suspicious cron persistence script (cron path + download/exec)"
        attack = "T1053.003"
        severity = 80
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $c1 = "/etc/cron.d/" ascii
        $c2 = "/etc/crontab" ascii
        $c3 = "/var/spool/cron" ascii
        $c4 = "crontab -" ascii
        $c5 = "@reboot" ascii
        $d1 = "curl " ascii
        $d2 = "wget " ascii
        $d3 = "chmod +x" ascii
        $d4 = "/bin/sh -c" ascii
        $d5 = "bash -c" ascii
        $d6 = "base64 -d" ascii

    condition:
        filesize < 5MB and 1 of ($c*) and 1 of ($d*)
}
