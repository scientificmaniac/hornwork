/*
  Hornwork 自研 YARA 规则：base64 编码命令
  覆盖"解码后直接执行"的典型链路：base64 -d | sh、eval(base64_decode(...))、
  PowerShell FromBase64String、python base64 解码执行等。
*/
rule base64_encoded_command
{
    meta:
        description = "Base64 encoded command decode-and-execute chain"
        attack = "T1140"
        severity = 70
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $b1 = "base64 -d" ascii nocase
        $b2 = "base64 --decode" ascii nocase
        $b3 = "base64 -D" ascii
        $b4 = "FromBase64String" ascii nocase
        $b5 = "base64.b64decode(" ascii
        $b6 = "eval(base64_decode(" ascii nocase
        $b7 = "exec(base64_decode(" ascii nocase
        $r1 = /(echo|printf)[^\n]{0,200}\|\s*base64\s+(-d|--decode)/ ascii
        $r2 = /(eval|exec)\s*\(\s*(base64_decode|atob)\s*\(/ ascii
        $r3 = /base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba|z|k|da)?sh/ ascii

    condition:
        filesize < 2MB and any of them
}
