rule MICEPP_Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell combinant décodage et téléchargement/exécution"
        severity = 75
        author = "MICEPP"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "FromBase64String" nocase ascii wide
        $net1 = "DownloadString" nocase ascii wide
        $net2 = "Invoke-WebRequest" nocase ascii wide
        $exec = "Invoke-Expression" nocase ascii wide
    condition:
        $ps and (1 of ($enc*)) and (1 of ($net*)) and $exec
}

rule MICEPP_Process_Injection_Primitives
{
    meta:
        description = "Combinaison d'API Windows compatible avec une injection de processus"
        severity = 80
        author = "MICEPP"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "OpenProcess" ascii wide
        $a5 = "NtUnmapViewOfSection" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MICEPP_Office_Autoexec_Macro_Strings
{
    meta:
        description = "Marqueurs d'auto-exécution et de lancement de commande dans un document Office"
        severity = 70
        author = "MICEPP"
    strings:
        $auto1 = "AutoOpen" nocase ascii wide
        $auto2 = "Document_Open" nocase ascii wide
        $auto3 = "Workbook_Open" nocase ascii wide
        $shell1 = "WScript.Shell" nocase ascii wide
        $shell2 = "Shell(" nocase ascii wide
        $shell3 = "CreateObject" nocase ascii wide
    condition:
        1 of ($auto*) and 2 of ($shell*)
}

rule MICEPP_Executable_High_Risk_System_Tools
{
    meta:
        description = "Exécutable référençant plusieurs outils système fréquemment détournés"
        severity = 55
        author = "MICEPP"
    strings:
        $s1 = "rundll32.exe" nocase ascii wide
        $s2 = "regsvr32.exe" nocase ascii wide
        $s3 = "mshta.exe" nocase ascii wide
        $s4 = "certutil.exe" nocase ascii wide
        $s5 = "bitsadmin" nocase ascii wide
        $s6 = "schtasks" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

