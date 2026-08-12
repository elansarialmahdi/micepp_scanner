rule MICEPP_Ransomware_Generic_Strings
{
    meta:
        description = "Generic ransomware ransom note indicators and encryption API patterns"
        severity = 90
        author = "MICEPP"
        mitre_ttp = "T1486"
    strings:
        $r1 = "your files have been encrypted" nocase ascii wide
        $r2 = "all your files are locked" nocase ascii wide
        $r3 = "decrypt_instructions" nocase ascii wide
        $r4 = "cryptencrypt" nocase ascii wide
        $r5 = "vssadmin delete shadows" nocase ascii wide
        $r6 = "wbadmin delete catalog" nocase ascii wide
    condition:
        2 of ($r*)
}

rule MICEPP_Webshell_PHP_Generic
{
    meta:
        description = "Generic PHP webshell features (eval, system, passthru, base64_decode)"
        severity = 85
        author = "MICEPP"
        mitre_ttp = "T1505.003"
    strings:
        $php = "<?php" ascii
        $f1 = "eval(" ascii
        $f2 = "system(" ascii
        $f3 = "exec(" ascii
        $f4 = "passthru(" ascii
        $f5 = "shell_exec(" ascii
        $f6 = "base64_decode(" ascii
        $f7 = "gzinflate(" ascii
    condition:
        $php and 3 of ($f*)
}

rule MICEPP_Obfuscated_VBScript_Downloader
{
    meta:
        description = "Obfuscated VBScript downloader using XMLHTTP and Adodb.Stream"
        severity = 75
        author = "MICEPP"
        mitre_ttp = "T1059.005"
    strings:
        $vbs1 = "MSXML2.XMLHTTP" nocase ascii wide
        $vbs2 = "Microsoft.XMLHTTP" nocase ascii wide
        $vbs3 = "Adodb.Stream" nocase ascii wide
        $vbs4 = "WScript.Shell" nocase ascii wide
        $vbs5 = "chr(" nocase ascii wide
    condition:
        (1 of ($vbs1, $vbs2)) and $vbs3 and $vbs4 and #vbs5 > 10
}
