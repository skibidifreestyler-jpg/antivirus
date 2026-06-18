rule EncodedPowerShell
{
    meta:
        description = "Encoded PowerShell execution"
        severity = "high"

    strings:
        $a = "powershell -enc" nocase
        $b = "FromBase64String" nocase
        $c = "iex(" nocase
        $d = "Invoke-Expression" nocase

    condition:
        any of them
}

rule JavaScriptObfuscation
{
    meta:
        description = "Common JavaScript obfuscation"

    strings:
        $a = "eval("
        $b = "atob("
        $c = "String.fromCharCode"
        $d = "unescape("
        $e = "Function("

    condition:
        2 of them
}

rule SuspiciousDownloader
{
    meta:
        description = "Downloader behavior"

    strings:
        $a = "wget"
        $b = "curl"
        $c = "Invoke-WebRequest"
        $d = "DownloadString"
        $e = "URLDownloadToFile"

    condition:
        any of them
}

rule CredentialTheft
{
    meta:
        description = "Credential theft indicators"

    strings:
        $a = "password"
        $b = "credentials"
        $c = "cookie"
        $d = "token"
        $e = "autofill"

    condition:
        3 of them
}

rule KeyloggerIndicators
{
    meta:
        description = "Potential keylogger"

    strings:
        $a = "GetAsyncKeyState"
        $b = "keylogger"
        $c = "keyboard"
        $d = "keypress"
        $e = "SetWindowsHookEx"

    condition:
        any of them
}

rule RATIndicators
{
    meta:
        description = "Remote Access Trojan indicators"

    strings:
        $a = "reverse shell"
        $b = "cmd.exe"
        $c = "powershell"
        $d = "socket"
        $e = "connect"

    condition:
        3 of them
}

rule PersistenceMechanism
{
    meta:
        description = "Windows persistence"

    strings:
        $a = "schtasks"
        $b = "startup"
        $c = "runonce"
        $d = "registry"
        $e = "reg add"

    condition:
        any of them
}

rule CryptoMiner
{
    meta:
        description = "Cryptominer indicators"

    strings:
        $a = "stratum"
        $b = "coinhive"
        $c = "xmrig"
        $d = "monero"
        $e = "mining"

    condition:
        2 of them
}

rule RansomwareIndicators
{
    meta:
        description = "Ransomware indicators"

    strings:
        $a = "aes-256"
        $b = "recover files"
        $c = "payment address"
        $d = "bitcoin"
        $e = "send btc"
        $f = "ransom"

    condition:
        2 of them
}

rule AntiAnalysis
{
    meta:
        description = "Anti-debugging / anti-VM"

    strings:
        $a = "isdebuggerpresent"
        $b = "anti-debug"
        $c = "anti-vm"
        $d = "vmware"
        $e = "virtualbox"
        $f = "sandbox"

    condition:
        any of them
}

rule EmbeddedExecutable
{
    meta:
        description = "Embedded executable references"

    strings:
        $a = ".exe"
        $b = ".dll"
        $c = ".bat"
        $d = ".ps1"
        $e = ".vbs"

    condition:
        3 of them
}

rule SuspiciousPython
{
    meta:
        description = "Suspicious Python execution"

    strings:
        $a = "os.system("
        $b = "subprocess.Popen("
        $c = "subprocess.run("
        $d = "exec("
        $e = "eval("

    condition:
        2 of them
}

rule SuspiciousHTML
{
    meta:
        description = "Suspicious HTML behavior"

    strings:
        $a = "document.write("
        $b = "onload="
        $c = "onclick="
        $d = "eval("
        $e = "unescape("

    condition:
        2 of them
}
