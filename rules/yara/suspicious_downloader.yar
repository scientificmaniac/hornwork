/*
  Hornwork 自研 YARA 规则：可疑下载器
  下载动作 + 落地执行/提权/管道执行组合；覆盖 wget/curl/certutil 等常见下载器。
*/
rule suspicious_downloader
{
    meta:
        description = "Suspicious downloader command chain (download + drop/exec)"
        attack = "T1105"
        severity = 70
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $d1 = "wget " ascii nocase
        $d2 = "curl " ascii nocase
        $d3 = "certutil -urlcache" ascii nocase
        $e1 = "-O /tmp/" ascii
        $e2 = "-o /tmp/" ascii
        $e3 = "| sh" ascii
        $e4 = "| bash" ascii
        $e5 = "chmod +x" ascii
        $e6 = "http.server" ascii

    condition:
        filesize < 2MB and 1 of ($d*) and 1 of ($e*)
}
