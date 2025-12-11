rule SuspiciousBatchFile
{
    meta:
        description = "Detects batch files with potentially malicious commands"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 3
        version = "2.0"
    
    strings:
        $cmd1 = "powershell" ascii nocase
        $cmd2 = "cmd.exe" ascii nocase
        $cmd3 = "wmic" ascii nocase
        $cmd4 = "netsh" ascii nocase
        $cmd5 = "reg add" ascii nocase
        $cmd6 = "schtasks" ascii nocase
        $download1 = "curl" ascii nocase
        $download2 = "wget" ascii nocase
        $download3 = "bitsadmin" ascii nocase
        $obfuscation1 = "%%" ascii nocase
        $obfuscation2 = "^" ascii nocase
        $obfuscation3 = "&" ascii nocase
        $obfuscation4 = "|" ascii nocase
        $obfuscation5 = "for" ascii nocase
        $obfuscation6 = "%%a" ascii nocase
        $execution1 = "exec" ascii nocase
        $execution2 = "run" ascii nocase
        $execution3 = "start" ascii nocase
        $persistence1 = "at " ascii nocase
        $persistence2 = "schtasks" ascii nocase
        $persistence3 = "reg add" ascii nocase
        $persistence4 = "HKLM" ascii nocase
        $persistence5 = "HKCU" ascii nocase
        $deletion1 = "del " ascii nocase
        $deletion2 = "erase " ascii nocase
        $deletion3 = "rd " ascii nocase
        $deletion4 = "rmdir " ascii nocase
        
    condition:
        filesize < 5000KB and
        3 of ($cmd*, $download*, $obfuscation*, $execution*, $persistence*, $deletion*)
}

rule ObfuscatedBatchFile
{
    meta:
        description = "Detects heavily obfuscated batch files"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 4
        version = "1.0"
    
    strings:
        $obfuscation1 = "%%" ascii nocase
        $obfuscation2 = "^" ascii nocase
        $obfuscation3 = "&" ascii nocase
        $obfuscation4 = "|" ascii nocase
        $obfuscation5 = "for" ascii nocase
        $obfuscation6 = "%%a" ascii nocase
        $obfuscation7 = "set " ascii nocase
        $encoding1 = "certutil" ascii nocase
        $encoding2 = "-decode" ascii nocase
        $encoding3 = "base64" ascii nocase
        $hidden1 = "attrib" ascii nocase
        $hidden2 = "+h" ascii nocase
        $hidden3 = "+s" ascii nocase
        $compression1 = "expand" ascii nocase
        $compression2 = "makecab" ascii nocase
        $script1 = "cscript" ascii nocase
        $script2 = "wscript" ascii nocase
        
    condition:
        filesize < 5000KB and
        5 of ($obfuscation*, $encoding*, $hidden*, $compression*, $script*)
}