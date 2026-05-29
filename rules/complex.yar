rule complex_regex_1 {
    meta:
        description = "Heavy regex rule simulating dynamic API resolutions"
    strings:
        // Regex with potential backtracking and case-insensitivity
        $re1 = /([a-zA-Z0-9_-]{3,15})\.(dll|exe|sys|ocx)/ nocase
        $re2 = /https?:\/\/[a-zA-Z0-9_\.-]+(\/[a-zA-Z0-9_\.-\?=&]+)*/
        $re3 = /User-Agent:\s*[a-zA-Z0-9_\.\/-]{5,50}/
    condition:
        all of them
}

rule complex_jump_strings_2 {
    meta:
        description = "Hex patterns with large or variable jumps"
    strings:
        $hex_jump1 = { 55 8b ec 83 ec [10-50] 8b 45 [0-8] 50 e8 }
        $hex_jump2 = { e8 ?? ?? ?? ?? 85 c0 74 [20-100] 5f 5d c3 }
        $hex_jump3 = { 31 c9 8a 44 0e ?? 80 f0 ?? 88 44 0e ?? 41 3b c8 72 }
    condition:
        2 of them
}

rule complex_loops_and_offsets_3 {
    meta:
        description = "Loops and entrypoint calculations to test condition compiler performance"
    strings:
        $a = "MZ"
        $b = "PE"
        $c = "UPX!"
    condition:
        $a at 0 and $b at (@a[1] + 60) and for any i in (1..#b) : ( @b[i] < 1024 ) and not $c
}
