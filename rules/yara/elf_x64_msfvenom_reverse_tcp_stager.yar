/*
    Detects the stripped 64-bit ELF reverse TCP stager analyzed in dfir-malware-analysis-lab
    (Module 3: Reverse Engineering & YARA Rule Engineering).
    MITRE ATT&CK: T1059.004 (Unix Shell), T1571 (Non-Standard Port)
    Reference: https://github.com/antonvikstrom/dfir-malware-analysis-lab
    Status: stable
*/

rule ELF_x64_MSFVenom_Reverse_TCP_Stager
{
    meta:
        author       = "Anton Vikstrom"
        description  = "Detects 64-bit ELF reverse TCP stager"
        hash_md5     = "ba81364271eb1fe4f2607e2f4972ed05"
        hash_sha256  = "71f598fc49eb3b8b240a75d9bcb742230a3010c386d044b501a9165a141246f6"
        reference    = "https://github.com/antonvikstrom/dfir-malware-analysis-lab"
        mitre_attack = "T1059.004, T1571"
        status       = "stable"

    strings:
        $elf_magic       = { 7F 45 4C 46 }
        $syscall_pattern = { 0F 05 }

    condition:
        $elf_magic at 0 and filesize < 5KB and #syscall_pattern >= 2
}
