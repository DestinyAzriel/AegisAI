rule SuspiciousPowerShell
{
    meta:
        description = "Detects PowerShell scripts with potentially malicious activities"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 4
        version = "2.0"
    
    strings:
        $ps1 = "powershell" ascii nocase
        $b64 = "FromBase64String" ascii nocase
        $invoke = "Invoke-Expression" ascii nocase
        $iex = "IEX" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $encoded = "-EncodedCommand" ascii nocase
        $download = "DownloadString" ascii nocase
        $webclient = "WebClient" ascii nocase
        $invoke2 = "Invoke-WebRequest" ascii nocase
        $invoke3 = "Invoke-Item" ascii nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "Set-ExecutionPolicy" ascii nocase
        $reflection1 = "Reflection.Assembly" ascii nocase
        $memory1 = "MemoryStream" ascii nocase
        $compression1 = "Compression.GzipStream" ascii nocase
        $obfuscation1 = "-f " ascii nocase
        $obfuscation2 = "-join" ascii nocase
        $obfuscation3 = "[char]" ascii nocase
        $obfuscation4 = "[byte]" ascii nocase
        $obfuscation5 = "[int]" ascii nocase
        $amsi1 = "amsi" ascii nocase
        $amsi2 = "AmsiScanBuffer" ascii nocase
        $amsi3 = "AmsiContext" ascii nocase
        
    condition:
        filesize < 1000KB and
        $ps1 and
        3 of ($b64, $invoke, $iex, $hidden, $encoded, $download, $webclient, $invoke2, $invoke3, $bypass*, $reflection*, $memory*, $compression*, $obfuscation*, $amsi*)
}

rule PowerShellDownloader
{
    meta:
        description = "Detects PowerShell download and execute patterns"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 5
        version = "1.0"
    
    strings:
        $download1 = "DownloadString" ascii nocase
        $download2 = "DownloadData" ascii nocase
        $download3 = "DownloadFile" ascii nocase
        $webclient = "WebClient" ascii nocase
        $invoke = "Invoke-Expression" ascii nocase
        $iex = "IEX" ascii nocase
        $exec1 = "Start-Process" ascii nocase
        $exec2 = "CreateProcess" ascii nocase
        $shell1 = "Shell.Application" ascii nocase
        $shell2 = "WScript.Shell" ascii nocase
        $run1 = "Run" ascii nocase
        $execute1 = "Execute" ascii nocase
        $b64 = "FromBase64String" ascii nocase
        $encoded = "-EncodedCommand" ascii nocase
        
    condition:
        filesize < 1000KB and
        2 of ($download*, $webclient) and
        2 of ($invoke, $iex, $exec*, $shell*, $run*, $execute*, $b64, $encoded)
}

rule ObfuscatedPowerShell
{
    meta:
        description = "Detects heavily obfuscated PowerShell scripts"
        author = "AegisAI"
        date = "2025-10-20"
        threat_level = 4
        version = "1.0"
    
    strings:
        $obfuscation1 = "-f " ascii nocase
        $obfuscation2 = "-join" ascii nocase
        $obfuscation3 = "[char]" ascii nocase
        $obfuscation4 = "[byte]" ascii nocase
        $obfuscation5 = "[int]" ascii nocase
        $obfuscation6 = "ForEach-Object" ascii nocase
        $obfuscation7 = "% {" ascii nocase
        $obfuscation8 = "Select-Object" ascii nocase
        $string1 = "System.String" ascii nocase
        $string2 = "String::" ascii nocase
        $replace1 = "-replace" ascii nocase
        $replace2 = "Replace(" ascii nocase
        $concat1 = "Concat(" ascii nocase
        $encoding1 = "System.Text.Encoding" ascii nocase
        $encoding2 = "UTF8.GetString" ascii nocase
        $encoding3 = "ASCII.GetString" ascii nocase
        
    condition:
        filesize < 1000KB and
        6 of ($obfuscation*, $string*, $replace*, $concat*, $encoding*)
}