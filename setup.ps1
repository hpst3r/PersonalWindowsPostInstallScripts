# launch PowerShell with:
# PowerShell -ExecutionPolicy Unrestricted

param(

    [Boolean]$disable_llmnr = 1,

    [Boolean]$enable_hyperv = 1,
        
        [Boolean]$install_wsl = 1,

            [Boolean]$install_debian = 1,

        [Boolean]$install_windows_sandbox = 1,

        [Boolean]$install_docker_ce = 0,

    # [Boolean]$install_adk = 0

    
    [Boolean]$use_registry_tweaks = 1,

        [Boolean]$taskbar_single_monitor = 1, # set taskbar to single screen only
        [Boolean]$taskbar_hide_search = 1, # hide the Search box
        [Boolean]$taskbar_hide_taskview = 1, # hide the Task View taskbar button
        [Boolean]$simple_context_menu = 1, # disable the new context menu

    [Boolean]$rename_computer = 1,
        
        [hashtable]$machines = @{

            # hash of hwid = friendly name
            "E059D9801FDE40FE35781C7C45D3C427D4C5CCADCFFF92854B9FCC998D2BC2AA" = "t14sg1a"
            

        },

    [Boolean]$install_programs = 1,

        [Boolean]$install_devtools = 1, # this grabs Scoop, the winget_devtools list, and WSL

            [Boolean]$install_scoop = 1,

                [Array]$scoop_early_deps = @("git", "aria2"),

                [Array]$scoop_buckets = @("java", "extras", "sysinternals"),

                [Array]$scoop_langs = @("python", "ruby", "go", "perl", "nodejs", "java/openjdk"),

                [Array]$scoop_utilities = @("sudo", "curl", "grep", "sed", "less", "touch"), # sudo MUST come first

        [Boolean]$use_winget = 1,

            # TODO: build array and install all desired packages from that
            [Boolean]$install_winget_dependencies = 1,
            [Array]$winget_dependencies = @("Microsoft.VCRedist.2015+.x64", "Microsoft.VCRedist.2015+.x86"),

            [Boolean]$install_winget_productivity = 1,
            [Array]$winget_productivity = @("Spotify.Spotify", "Mozilla.Firefox.DeveloperEdition", "Microsoft.Office"),

            [Boolean]$install_winget_utilities = 1,
            [Array]$winget_utilities = @("7zip.7zip", "REALiX.HWiNFO", "Bitwarden.Bitwarden"),

            [Boolean]$install_winget_extras = 1,
            [Array]$winget_extras = @("Nlitesoft.Nlite", "SyncTrayzor.SyncTrayzor", "Microsoft.PowerToys"),

            [Boolean]$install_winget_devtools = 1,
            [Array]$winget_devtools = @("Git.Git", "GitHub.cli", "Microsoft.VisualStudioCode", "Microsoft.VisualStudioCode.CLI", "Microsoft.PowerShell"),

            [Boolean]$install_winget_networking = 1,
            [Array]$winget_networking = @("Insecure.Npcap", "WiresharkFoundation.Wireshark", "PuTTY.PuTTY"),

            [Boolean]$install_winget_3d = 1,
            [Array]$winget_3d = @("UltiMaker.Cura")

)

# https://learn.microsoft.com/en-us/windows/package-manager/winget/
function Install-Winget {

    $progressPreference = 'silentlyContinue'
    Write-Information "Downloading WinGet and its dependencies..."
    Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
    Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
    Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

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

function Set-RegistryValue {

    [CmdletBinding()]
    param (
        [String]$key_path,
        [String]$value_name,
        [String]$value_type,
        [int]$value
    )

    # if exists set value
    if (Get-ItemProperty -Path $key_path -Name $value_name) {
        Set-ItemProperty -Path $key_path -Name $value_name -value $value -Force
    } else { # if not exists create value
        New-ItemProperty -Path $key_path -Name $value_name -value $value -Type $value_type
    }

}

# TODO: not working as far as I know
function Install-Adk {

    [String]$AdkPath = Convert-Path "~\Downloads\adksetup.exe"

    Invoke-WebRequest -uri "https://go.microsoft.com/fwlink/?linkid=2243390" -outfile $AdkPath

    & $AdkPath /quiet /installpath C:\ADK /features +

}

Function New-RegistryKey {

    param (
        [String]$key_path
    )

    if (-not (Test-Path -Path $key_path)) {

        New-Item -Path $key_path -Force

    }

}

Function Get-Hash {
    
    param (
        [String]$text,
        [String]$algorithm
    )

    Return Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$text)) -Algorithm $algorithm

}

# check if script is elevated by evaluating well-known Administrator GIDs.
[Boolean]$is_administrator = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
# if not running elevated, fail
if (($is_administrator)) {
    Write-Host "@@@ This script must not be run as Administrator. Exiting. @@@"
    Exit 1
}

# basics

Set-TimeZone -Name "Eastern Standard Time"
# TODO: fix - requires admin
# sudo config --enable normal

if ($use_registry_tweaks) {

    # hide the taskbar on all but the primary monitor
    if ($taskbar_single_monitor) {
        Set-RegistryValue -key_path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -value_name 'MMTaskbarEnabled' -value_type 'DWord' -value 0
    }

    # hide the search bar on the taskbar
    if ($taskbar_hide_search) {
        Set-RegistryValue -key_path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -value_name 'SearchBoxTaskbarMode' -value_type 'DWord' -value 0
    }

    # hide the task view button on the taskbar
    if ($taskbar_hide_taskview) { 
        Set-RegistryValue -key_path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -value_name 'ShowTaskViewButton' -value_type 'DWord' -value 0
    }

    # disables the new context menu
    if ($simple_context_menu) {

        New-RegistryKey -key_path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'

        Set-RegistryValue -key_path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -value_name '(Default)' -value_type String -value ''
        
    }

    # refresh Explorer to apply changes immediately
    Stop-Process -Name Explorer -Force
}

# disable link-local multicast name resolution (LLMNR), which forces the use of a DNS server
if ($disable_llmnr) {

    Write-Host("+++ Disabling LLMNR +++")
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force

}

# Windows tweaks: disable Netbios - this will only disable Netbios on adapters that are currently up
# TODO: spawn a script on network adapter change to kill netbios?
# (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2)

if ($enable_hyperv) {
    
    Write-Host("+++ Enabling Hyper-V +++")
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

    if ($install_docker_ce) {

        # this reboots the computer unprompted in the middle of the script, thanks Microsoft
        # TODO: fix before implementing
        <# if ($install_docker_ce) {

            Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1" -o install-docker-ce.ps1
            .\install-docker-ce.ps1
            
        } #>
        
    }

    if ($install_wsl) {
        Write-Host("+++ Installing WSL +++")
        if ($install_debian) {
            Write-Host("+++ WSL: Installing Debian +++")
            wsl.exe --install -d Debian
        } else {
            Write-Host("+++ WSL: Installing default distro +++")
            wsl.exe --install
        }
    }
    

    if ($install_windows_sandbox) {

        Write-Host("+++ Enabling Windows Sandbox +++")
        # this requires elevation and does not prompt
        # TODO: fix above
        Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online -NoRestart -ErrorAction Stop

    }

}

if ($install_programs) {

    Write-Host("+++ Installing applications +++")

    if ($install_devtools -and $install_scoop) {
        
        Write-Host("+++ pre-install for Scoop - check if it already exists +++")
    
        if (![bool](Get-Command scoop)) {
    
            Write-Host("+++ Scoop not found. Installing the Scoop package manager +++")
            Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin" -ErrorVariable ScoopErrVar -ErrorAction Inquire
    
        } else { Write-Host("+++ Scoop was found. Skipping installation +++") }
    
        # install the Scoop packages necessary to add buckets
        Install-ScoopRange($scoop_early_deps)
        # add Scoop repos (buckets)
        Add-ScoopBucketRange($scoop_buckets)
        # install the Scoop packages we want
        Install-ScoopRange($scoop_utilities)
        Install-ScoopRange($scoop_langs)
    
    } else { Write-Host("--- Skipping development group ---") }
    
    # Install apps from the Microsoft Store with winget
    if ($use_winget) {
    
        if (-not (Get-Command winget.exe)) { Install-Winget }
    
        Write-Host("+++ Beginning installation of Windows Store apps. +++")
    
        if ($install_winget_dependencies) { Install-WingetRange $winget_dependencies }
    
        if ($install_winget_productivity) { Install-WingetRange $winget_productivity }
    
        if ($install_winget_utilities) { Install-WingetRange $winget_utilities }
    
        if ($install_winget_devtools -and $install_devtools) { Install-WingetRange $winget_devtools }
    
        if ($install_winget_extras) { Install-WingetRange $winget_extras } 
    
        if ($install_winget_networking) { Install-WingetRange $winget_networking }
    
    }

} else { Write-Host("--- Package installation bypassed ---") }

if ($rename_computer) {

    # match hash of device S/Ns in a hash table ($machines) with friendly names - not posting my S/Ns on github

    # get SHA256 from the serial number
    $device_serial = Get-Hash -text (WMIC.exe bios get serialnumber) -algorithm SHA256

    # match in LUT for friendly name
    Rename-Computer "liam-$($machines[$device_serial])"

}

Write-Host("!!! Script completed !!!")
Exit 0