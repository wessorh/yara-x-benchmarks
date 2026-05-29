rule teddy_1 {
    meta:
        description = "Simple rule where YARA-X uses Teddy instead of Aho-Corasick"
    strings:
        $str1 = "VirtualAlloc" 
        $str2 = "CreateRemoteThread"
        $str3 = "WriteProcessMemory"
        $str4 = "GetProcAddress"
        $str5 = "LoadLibraryA"
    condition:
        3 of them
}