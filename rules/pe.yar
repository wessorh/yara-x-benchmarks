import "pe"

rule pe_1 {
    meta:
        description = "Exercises PE module section parsing"
    condition:
        pe.number_of_sections >= 3 and
        pe.number_of_sections <= 10 and
        for any section in pe.sections : (
            section.name == ".text" and
            (section.characteristics & 0x20000000) != 0 // SECTION_MEM_EXECUTE
        )
}


rule pe_3 {
    meta:
        description = "Exercises PE rich header checks"
    condition:
        pe.is_pe and pe.number_of_resources > 0 and (
            pe.linker_version.major > 10 or
            pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
        )
}
