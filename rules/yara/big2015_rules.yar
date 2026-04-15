/*
    YARA Rules for Microsoft BIG-2015 Malware Dataset Detection
    
    These rules target common patterns found in the BIG-2015 dataset's
    nine malware families. Rules use a combination of string patterns,
    byte sequences, and file characteristics for detection.
    
    Families covered:
    1. Ramnit       - Worm/Virus
    2. Lollipop     - Adware
    3. Kelihos_ver3 - Backdoor/Botnet  
    4. Vundo        - Trojan
    5. Simda        - Backdoor
    6. Tracur       - Trojan Downloader
    7. Kelihos_ver1 - Backdoor/Botnet
    8. Obfuscator   - Obfuscated Malware
    9. Gatak        - Backdoor
*/


rule Ramnit_Worm : malware worm ramnit
{
    meta:
        description = "Detects Ramnit worm family from BIG-2015 dataset"
        author = "Detection System"
        family = "Ramnit"
        severity = 3
        reference = "Microsoft BIG-2015 Class 1"

    strings:
        $s1 = "VB5!" ascii
        $s2 = "GetProcAddress" ascii
        $s3 = "VirtualAlloc" ascii
        $s4 = "WriteProcessMemory" ascii
        $inject = { 55 8B EC 83 EC ?? 56 57 8B 7D ?? }
        $mutex = "KyUffThOkYwRRtgPP" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) or $inject or $mutex)
}


rule Kelihos_Botnet : malware backdoor botnet kelihos
{
    meta:
        description = "Detects Kelihos botnet variants (v1 and v3)"
        author = "Detection System"
        family = "Kelihos"
        severity = 4
        reference = "Microsoft BIG-2015 Class 3 & 7"

    strings:
        $p2p1 = "bitcoin" ascii nocase
        $p2p2 = "wallet" ascii nocase
        $net1 = "SMTP" ascii
        $net2 = "recv" ascii
        $net3 = "send" ascii
        $net4 = "WSAStartup" ascii
        $spam = "Content-Type: multipart" ascii
        $crypt = { 8B 45 ?? 35 ?? ?? ?? ?? 89 45 }
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (2 of ($p2p*) and 2 of ($net*)) or
        ($spam and $crypt)
}


rule Vundo_Trojan : malware trojan vundo
{
    meta:
        description = "Detects Vundo/Virtumonde trojan family"
        author = "Detection System"
        family = "Vundo"
        severity = 3
        reference = "Microsoft BIG-2015 Class 4"

    strings:
        $dll1 = "DllRegisterServer" ascii
        $dll2 = "DllUnregisterServer" ascii
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg2 = "CLSID" ascii nocase
        $bho = "Browser Helper Object" ascii nocase
        $inject = "NtCreateThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (2 of ($dll*) and 1 of ($reg*)) or
        ($bho and $inject)
}


rule Simda_Backdoor : malware backdoor simda
{
    meta:
        description = "Detects Simda backdoor family"
        author = "Detection System"
        family = "Simda"
        severity = 4
        reference = "Microsoft BIG-2015 Class 5"

    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "InternetConnectA" ascii
        $api3 = "HttpOpenRequestA" ascii
        $api4 = "HttpSendRequestA" ascii
        $hosts = "\\drivers\\etc\\hosts" ascii nocase
        $dns = "DnsQuery" ascii
        $hook = "SetWindowsHookEx" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($api*) and ($hosts or $dns)) or
        ($hook and 2 of ($api*))
}


rule Tracur_Downloader : malware trojan dropper tracur
{
    meta:
        description = "Detects Tracur trojan downloader family"
        author = "Detection System"
        family = "Tracur"
        severity = 3
        reference = "Microsoft BIG-2015 Class 6"

    strings:
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "UrlMkSetSessionOption" ascii
        $tmp = "\\Temp\\" ascii nocase
        $exec1 = "ShellExecute" ascii
        $exec2 = "CreateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (1 of ($dl*) and $tmp and 1 of ($exec*))
}


rule Obfuscated_Malware : suspicious packed obfuscator
{
    meta:
        description = "Detects heavily obfuscated/packed malware"
        author = "Detection System"
        family = "Obfuscator"
        severity = 2
        reference = "Microsoft BIG-2015 Class 8"

    strings:
        $upx = "UPX0" ascii
        $aspack = ".aspack" ascii
        $themida = "Themida" ascii
        $vmp = ".vmp" ascii
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $anti_dbg = "IsDebuggerPresent" ascii
        $anti_vm1 = "VMwareVMware" ascii
        $anti_vm2 = "VBoxGuest" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($upx, $aspack, $themida, $vmp)) or
            ($nop_sled and $anti_dbg) or
            (1 of ($anti_vm*) and $anti_dbg)
        )
}


rule Gatak_Backdoor : malware backdoor gatak
{
    meta:
        description = "Detects Gatak backdoor family"
        author = "Detection System"
        family = "Gatak"
        severity = 4
        reference = "Microsoft BIG-2015 Class 9"

    strings:
        $steg1 = "BM" ascii
        $jpeg = { FF D8 FF }
        $png = { 89 50 4E 47 }
        $http = "http://" ascii
        $cmd1 = "cmd /c" ascii nocase
        $cmd2 = "powershell" ascii nocase
        $reg = "RegSetValueEx" ascii
        $crypto = { 31 C0 [2-4] F7 }

    condition:
        filesize < 10MB and
        (
            ($http and 1 of ($cmd*) and $reg) or
            (($steg1 at 0 or $jpeg at 0 or $png at 0) and 1 of ($cmd*) and $crypto)
        )
}


rule Generic_Suspicious_PE : suspicious
{
    meta:
        description = "Generic suspicious PE file characteristics"
        author = "Detection System"
        severity = 1

    strings:
        $mz = "MZ" ascii
        $str_cmd = "cmd.exe" ascii nocase
        $str_ps = "powershell" ascii nocase
        $str_reg = "HKEY_LOCAL_MACHINE" ascii nocase
        $str_net1 = "WinHttpOpen" ascii
        $str_net2 = "InternetOpen" ascii
        $str_inject = "NtWriteVirtualMemory" ascii
        $str_crypt = "CryptEncrypt" ascii

    condition:
        $mz at 0 and filesize < 20MB and
        3 of ($str_*)
}
