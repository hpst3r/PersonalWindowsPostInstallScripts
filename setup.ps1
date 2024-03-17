# check if script is elevated by evaluating well-known Administrator GIDs.
function Get-BoolRunningAsAdministrator {
    return [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}

function Get-BoolIsInstalled {

    [CmdletBinding()]
    param (
        [string]$program
    )

    return [bool](Get-Command $program)
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

# Script proper

# This needs to happen first manually. Allow Administrator to run scripts
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Windows tweaks: disable Netbios - this will only disable Netbios on adapters that are currently up
# TODO: spawn a script on network adapter change to kill netbios
(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2)

# Windows tweaks: disable Link-Local Multicast Name Resolution (LLMNR) which forces use of a DNS server
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force

# Scaffolding: initialize Script Host shell object for diag popups
$wshell = New-Object -ComObject Wscript.Shell
# if not running elevated, fail
if ((Get-BoolRunningAsAdministrator)) {
    Write-HostAndPopup("This script must not be run as Administrator. Exiting.")
    Exit
}

# Scaffolding: install the Scoop package manager if it is not already present
if (!(Get-BoolIsInstalled("scoop"))) {
    Write-Host("+++ Scoop not found. Installing the Scoop package manager +++")
    Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin" -ErrorVariable ScoopErrVar -ErrorAction Inquire
} else {
    Write-Host("+++ Scoop was found. Skipping installation +++")
}

# Reset ExecutionPolicy to Restricted once Scoop is installed - this prevents Administrator from running scripts
# Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser

# Install apps from the Microsoft Store with winget

Write-Host("+++ Beginning installation of Windows Store apps. Expect installer prompts +++")
# Group - System utilities and common nice-to-haves
# Spotify music player
Write-Host("+++ Installing Spotify. Expect failure[29] if the application is already installed +++")
winget install Spotify.Spotify
# Bitwarden password manager
winget install Bitwarden.Bitwarden
# Mozilla Firefox Developer Edition
winget install Mozilla.Firefox.DeveloperEdition
# hwinfo64 system sensor monitoring software
winget install REALiX.HWiNFO
# 7zip
winget install 7zip.7zip
# Syncthing (SyncTrayzor)
winget install SyncTrayzor.SyncTrayzor
# ExplorerPatcher
winget install valinet.ExplorerPatcher

# Group - Development tools and runtimes
# Visual Studio Code
winget install Microsoft.VisualStudioCode
winget install Microsoft.VisualStudioCode.CLI
# Git
winget install Git.Git
# Github CLI
winget install GitHub.cli
# Visual C++ Redistributable
winget install Microsoft.VCRedist.2015+.x64
winget install Microsoft.VCRedist.2015+.x86

# Group - Networking
# npcap
winget install Insecure.Npcap
# wireshark
winget install WiresharkFoundation.Wireshark

Write-Host("+++ Beginning installation of Scoop packages +++")
# Install apps from the Scoop package manager
scoop install git aria2
# add Scoop buckets
scoop bucket add java
scoop bucket add extras
scoop bucket add sysinternals
# install applications
scoop install sudo
scoop install python ruby go perl nodejs
scoop install java/openjdk
scoop install curl grep sed less touch
# -- null --

# Install Windows Subsystem for Linux with Debian instead of default Ubuntu
if (!(Get-BoolIsInstalled("wsl"))) {
    Write-Host("+++ WSL not found. Installing wsl (wsl.exe --install -d debian) +++")
    wsl.exe --install -d debian
} else {
    Write-Host("+++ WSL was found. Skipping installation +++")
}

# Cleanup: Reset ExecutionPolicy to Restricted - this prevents the user from running scripts
# Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser