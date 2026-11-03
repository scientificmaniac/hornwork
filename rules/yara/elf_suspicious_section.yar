/*
  Hornwork 自研 YARA 规则：可疑 ELF 节名 / 加壳特征
  ELF 魔数 + 异常节名（.evil/.hidden/.crypt 等）或 UPX 加壳标记。
  纯结构特征，不依赖样本内容语义。
*/
rule elf_suspicious_section
{
    meta:
        description = "ELF binary with suspicious section names or packer markers"
        attack = "T1027.009"
        severity = 75
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
        $s4 = ".evil" ascii
        $s5 = ".hidden" ascii
        $s6 = ".crypt" ascii
        $s7 = ".payload" ascii
        $s8 = ".stub" ascii
        $s9 = ".packed" ascii

    condition:
        uint32(0) == 0x464c457f and any of ($s*)
}
