rule simple_text_match_1 {
    meta:
        description = "Simple rule matching standard malware strings"
        severity = "low"
    strings:
        $str1 = "VirtualAlloc" ascii wide nocase
        $str2 = "CreateRemoteThread" ascii wide nocase
        $str3 = "WriteProcessMemory" ascii wide nocase
        $str4 = "GetProcAddress" ascii wide
        $str5 = "LoadLibraryA" ascii wide
    condition:
        3 of them
}

rule simple_hex_match_2 {
    meta:
        description = "Simple rule matching standard executable hex sequences"
        severity = "low"
    strings:
        $hex1 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff }
        $hex2 = { 55 8b ec 81 ec }
        $hex3 = { e8 [4-12] 5f 5d c3 }
    condition:
        $hex1 and ($hex2 or $hex3)
}

rule simple_mixed_match_3 {
    meta:
        description = "Simple mixed text and hex matching"
        severity = "medium"
    strings:
        $text = "cmd.exe /c" ascii wide nocase
        $hex = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 }
    condition:
        $text or $hex
}
