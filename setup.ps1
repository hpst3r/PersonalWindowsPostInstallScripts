# This needs to happen first manually. Allow Administrator to run scripts
# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
# Install or update Winget first!
# https://apps.microsoft.com/detail/9nblggh4nns1?rtc=1&hl=en-us&gl=US#activetab=pivot:overviewtab

# https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install

[Boolean]$disable_llmnr = 0

[Boolean]$enable_hyperv = 1
    
    [Boolean]$install_wsl = 1

        [Boolean]$install_debian = 1

[Boolean]$install_adk = 1

[Boolean]$install_devtools = 1 # this grabs Scoop, the winget_devtools list, and WSL

    [Boolean]$install_scoop = 1

        [Array]$scoop_early_deps = @("git", "aria2")

        [Array]$scoop_buckets = @("java", "extras", "sysinternals")

        [Array]$scoop_langs = @("python", "ruby", "go", "perl", "nodejs", "java/openjdk")

        [Array]$scoop_utilities = @("sudo", "curl", "grep", "sed", "less", "touch") # sudo MUST come first

[Boolean]$use_winget = 1

    [Boolean]$install_winget_dependencies = 1
    [Array]$winget_dependencies = @("Microsoft.VCRedist.2015+.x64", "Microsoft.VCRedist.2015+.x86")

    [Boolean]$install_winget_niceties = 1
    [Array]$winget_niceties = @("Spotify.Spotify", "Mozilla.Firefox.DeveloperEdition", "SyncTrayzor.SyncTrayzor", "Microsoft.PowerToys")

    [Boolean]$install_winget_utilities = 1
    [Array]$winget_utilities = @("7zip.7zip", "REALiX.HWiNFO", "Bitwarden.Bitwarden", "Nlitesoft.Nlite")

    [Boolean]$install_winget_extras = 1
    [Array]$winget_extras = @("valinet.ExplorerPatcher")

    [Boolean]$install_winget_devtools = 1
    [Array]$winget_devtools = @("Git.Git", "GitHub.cli", "Microsoft.VisualStudioCode", "Microsoft.VisualStudioCode.CLI")

    [Boolean]$install_winget_networking = 1
    [Array]$winget_networking = @("Insecure.Npcap", "WiresharkFoundation.Wireshark", "PuTTY.PuTTY")

# check if script is elevated by evaluating well-known Administrator GIDs.
function Get-BoolRunningAsAdministrator {
    return [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}

# given a string message, write to host and a basic Script Host popup
function Write-HostAndPopup {

    [CmdletBinding()]
    param (
        [string]$message
    )

    Write-Host($message)
    $wshell.Popup($message)

}

function Install-WingetRange {

    [CmdletBinding()]
    param (
        [Array]$winget_ids
    )

    foreach ($winget_id in $winget_ids) {
        winget install $winget_id
    }

}

function Install-ScoopRange {

    [CmdletBinding()]
    param (
        [Array]$scoop_programs
    )

    foreach ($scoop_program in $scoop_programs) {
        scoop install $scoop_program
    }

}

function Add-ScoopBucketRange {

    [CmdletBinding()]
    param (
        [Array]$scoop_buckets
    )

    foreach ($scoop_bucket in $scoop_buckets) {
        scoop bucket add $scoop_bucket
    }

}

# not working as far as I know
function Install-Adk {

    [String]$AdkPath = Convert-Path "~\Downloads\adksetup.exe"

    Invoke-WebRequest -uri "https://go.microsoft.com/fwlink/?linkid=2243390" -outfile $AdkPath

    & $AdkPath /quiet /installpath C:\ADK /features +

}

# Scaffolding: initialize Script Host shell object for diag popups
$wshell = New-Object -ComObject Wscript.Shell
# if not running elevated, fail
if ((Get-BoolRunningAsAdministrator)) {
    Write-HostAndPopup("This script must not be run as Administrator. Exiting.")
    Exit
}

if ($disable_llmnr) {

    # disable Link-Local Multicast Name Resolution (LLMNR), which forces use of a DNS server

    Write-Host("+++ Disabling LLMNR +++")
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force

}

# Windows tweaks: disable Netbios - this will only disable Netbios on adapters that are currently up
# TODO: spawn a script on network adapter change to kill netbios
# (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2)

if ($enable_hyperv) {

    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -IncludeManagementTools

}

if ($install_adk) { Install-Adk }

# Scaffolding: install the Scoop package manager if it is not already present
if ($install_scoop -and $install_devtools) {

    Write-Host("+++ pre-install for Scoop - check if software exists +++")

    if (![bool](Get-Command scoop)) {

        Write-Host("+++ Scoop not found. Installing the Scoop package manager +++")
        Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin" -ErrorVariable ScoopErrVar -ErrorAction Inquire

    } else {

        Write-Host("+++ Scoop was found. Skipping installation +++")

    }

    Install-ScoopRange($scoop_early_deps)
    Add-ScoopBucketRange($scoop_buckets)
    Install-ScoopRange($scoop_utilities)
    Install-ScoopRange($scoop_langs)

} else {
    Write-Host("--- Scoop installation bypassed ---")
}

# Install apps from the Microsoft Store with winget
if ($use_winget) {
    Write-Host("+++ Beginning installation of Windows Store apps. Expect installer prompts +++")
    if ($install_winget_dependencies) {
        Install-WingetRange $winget_dependencies
    }
    if ($install_winget_niceties) {
        Install-WingetRange $winget_niceties
    }
    if ($install_winget_utilities) {
        Install-WingetRange $winget_utilities
    }
    if ($install_winget_devtools -and $install_devtools) {
        Install-WingetRange $winget_devtools
    }
    if ($install_winget_extras) {
        Install-WingetRange $winget_extras
    }
    if ($install_winget_networking) {
        Install-WingetRange $winget_networking
    }
}

if ($enable_hyperv -and $install_wsl) {
    Write-Host("+++ Installing WSL +++")
    if ($install_debian) {
        Write-Host("+++ WSL: Installing Debian +++")
        wsl.exe --install -d Debian
    } else {
        Write-Host("+++ WSL: Installing default distro +++")
        wsl.exe --install
    }
}

Write-Host("!!! Script completed successfully !!!")
Exit 0

# this just never installs Debian on normal W11 (that has wsl by default)
# Install Windows Subsystem for Linux with Debian instead of default Ubuntu
# if (!(Get-BoolIsInstalled("wsl"))) {
#   Write-Host("+++ WSL not found. Installing wsl (wsl.exe --install -d debian) +++")
#    wsl.exe --install -d debian
#} else {
#    Write-Host("+++ WSL was found. Skipping installation +++")
#}

# Cleanup: Reset ExecutionPolicy to Restricted - this prevents the user from running scripts (default setting on 21H2 desktop)
# Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser