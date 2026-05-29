rule complex_regex_1 {
    meta:
        description = "Heavry regular expressions"
    strings:
        $re1 = /([a-zA-Z0-9_-]{3,15})\.(dll|exe|sys|ocx)/ nocase
        $re2 = /https?:\/\/[a-zA-Z0-9_\.-]+(\/[a-zA-Z0-9_\.-\?=&]+)*/
        $re3 = /User-Agent:\s*[a-zA-Z0-9_\.\/-]{5,50}/
    condition:
        all of them
}