/*
  Hornwork 自研 YARA 规则：挖矿程序特征
  覆盖矿池协议、常见矿工名称与算法串；同时匹配 shell 下载矿工的脚本。
*/
rule crypto_miner
{
    meta:
        description = "Crypto mining binary or drop script markers"
        attack = "T1496"
        severity = 85
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $m1 = "stratum+tcp://" ascii nocase
        $m2 = "stratum+ssl://" ascii nocase
        $m3 = "stratum2+tcp://" ascii nocase
        $m4 = "xmrig" ascii nocase
        $m5 = "minerd" ascii nocase
        $m6 = "cryptonight" ascii nocase
        $m7 = "randomx" ascii nocase
        $m8 = "c3pool" ascii nocase
        $m9 = "minexmr" ascii nocase
        $m10 = "--donate-level" ascii nocase
        $m11 = "monero-wallet" ascii nocase
        $m12 = "kawpow" ascii nocase

    condition:
        filesize < 50MB and any of them
}
