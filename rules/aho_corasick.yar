rule teddy_1 {
    meta:
        description = "Simple rule where the scanning time is dominated by Aho-Corasick"
    strings:
        $str1 = "VirtualAlloc" wide ascii nocase
        $str2 = "CreateRemoteThread" wide ascii nocase
        $str3 = "WriteProcessMemory" wide ascii nocase
        $str4 = "GetProcAddress" wide ascii nocase
        $str5 = "LoadLibraryA" wide ascii nocase
    condition:
        3 of them
}