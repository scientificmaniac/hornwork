/*
  Hornwork 自研 YARA 规则：凭据文件访问/转储
  命中 /etc/shadow、/etc/gshadow 与复制/编码/外传动作的组合，或已知影子文件提取工具名。
*/
rule credential_access_shadow
{
    meta:
        description = "Credential file access or shadow dump tooling"
        attack = "T1003.008"
        severity = 80
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $s1 = "/etc/shadow" ascii
        $s2 = "/etc/gshadow" ascii
        $c1 = "cp " ascii
        $c2 = "cat " ascii
        $c3 = "base64 " ascii
        $c4 = "curl " ascii
        $c5 = "wget " ascii
        $k1 = "unshadow" ascii nocase
        $k2 = "john " ascii nocase
        $k3 = "hashcat" ascii nocase
        $k4 = "mimipenguin" ascii nocase
        $k5 = "lazagne" ascii nocase

    condition:
        filesize < 2MB and
        (
            1 of ($k*)
            or
            (1 of ($s*) and 1 of ($c*))
        )
}
