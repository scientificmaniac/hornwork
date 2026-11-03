/*
  Hornwork 自研 YARA 规则：无文件（fileless）执行特征
  memfd_create / fexecve / /proc/<pid>/fd 组合是内存马与无文件载荷的典型标志。
*/
rule fileless_memfd
{
    meta:
        description = "Fileless execution markers (memfd_create / fexecve / /proc/pid/fd)"
        attack = "T1620"
        severity = 75
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $f1 = "memfd_create" ascii
        $f2 = "/proc/self/fd/" ascii
        $f3 = "fexecve" ascii
        $f4 = "/proc/%d/fd/" ascii
        $f5 = "memfd:" ascii
        $f6 = "shm_open" ascii

    condition:
        filesize < 2MB and 2 of them
}
