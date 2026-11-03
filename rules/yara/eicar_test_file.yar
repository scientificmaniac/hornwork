/*
  Hornwork 自研 YARA 规则：EICAR 标准反病毒测试串

  EICAR 测试文件是公开的反病毒产品联调样本（68 字节），不含真实恶意代码，
  仅用于验证静态检测链路是否具备"已知测试串"的检出能力。
*/
rule eicar_test_file
{
    meta:
        description = "EICAR standard antivirus test string"
        attack = "T1005"
        severity = 100
        source = "hornwork-self"
        author = "hornwork rules"
        date = "2026-11-03"

    strings:
        $eicar_ascii = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
        $eicar_hex = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }

    condition:
        filesize < 1MB and any of them
}