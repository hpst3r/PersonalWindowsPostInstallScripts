#Requires -RunAsAdministrator
<#
    .SYNOPSIS
    Installs applications, features and registry tweaks. For a full manifest, see config.json.
#>
BEGIN {
    # https://learn.microsoft.com/en-us/windows/package-manager/winget/
    function Install-Winget {

        Write-Host "Installing WinGet PowerShell module from PSGallery..."

        Install-PackageProvider -Name NuGet -Force

        Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery

        Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."

        Repair-WinGetPackageManager

    }

    # TODO: add or remove elevation when required
    # TODO: find a way to query ElevationRequirement
    function Install-WingetPackages {

        [CmdletBinding()]
        param (
            [PSObject]$WingetPackages
        )

        foreach ($WingetPackage in $WingetPackages) {
            Write-Host `
            "+++ Installing package $($WingetPackage.PackageFriendlyName) +++"
            winget install $WingetPackage.PackageId --accept-source-agreements --accept-package-agreements
        }

    }

    function Install-ScoopRange {

        [CmdletBinding()]
        param (
            [Array]$ScoopPackages
        )

        foreach ($ScoopPackage in $ScoopPackages) {
            scoop install $ScoopPackage
        }

    }

    function Add-ScoopBucketRange {

        [CmdletBinding()]
        param (
            [Array]$ScoopBuckets
        )

        foreach ($ScoopBucket in $ScoopBuckets) {
            scoop bucket add $ScoopBucket
        }

    }

    function Set-RegistryValue {

        [CmdletBinding()]
        param (
            [String]$KeyPath,
            [String]$ValueName,
            [String]$ValueType,
            $Value
        )

        $PathNameValue = @{
            Path = $KeyPath
            Name = $ValueName
            Value = $Value
        }

        # if the registry key does not exist, create it and set desired value
        if (-not (Test-Path -Path $KeyPath)) {

            New-Item `
                -ItemType RegistryKey `
                -Path $KeyPath `
                -Force

            New-ItemProperty `
                @PathNameValue `
                -PropertyType $ValueType


            return Get-ItemProperty `
                -Path $KeyPath `
                -Name $ValueName
        }

        # if the key exists, just set the value
        # if the value exists, just set it
        if (Get-ItemProperty -Path $KeyPath -Name $ValueName) {

            Set-ItemProperty @PathNameValue

        } else { # if the value doesn't exist, create it

            New-ItemProperty `
                @PathNameValue `
                -PropertyType $ValueType

        }

    }

    Function Get-Hash {
        
        param (
            [String]$Text,
            [String]$Algorithm = 'md5'
        )

        Return Get-FileHash `
            -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$Text)) `
            -Algorithm $Algorithm

    }

} PROCESS {

    # load config.json to PSObject $Configuration
    $Configuration = Get-Content .\config.json | ConvertFrom-Json

    Start-Transcript `
        -Path "setup-$(Get-Date -UFormat %s).log"

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host `
        "Beginning execution: version $(git rev-parse --short HEAD) at $(Get-Date -UFormat %s)."

    # basics

    # if the timezone requested exists, use it. Otherwise, use EST
    Write-Host `
        "Attempting to set system timezone to $($Configuration.TimeZone)"
    Set-TimeZone `
        $(
            if ( (Get-TimeZone $Configuration.TimeZone) ) {
                
                Write-Host "Timezone passed validation - setting system timezone to requested $($Configuration.TimeZone)."
                
                $Configuration.TimeZone

            } else {
                
                Write-Error `
                    "Timezone $($Configuration.TimeZone) is not valid. Setting system timezone to Eastern Standard Time."
                
                'Eastern Standard Time'

            }
        )

    if ($Configuration.Registry.MakeChanges) {

        # TODO: why is the below edit necessary or desired? I forgot.
        # set CLRF=0 in HKCU\Software\Microsoft\Telnet

        # show taskbar on all (1, default) or main (0) monitor(s)
        $ShowTaskbarPrimaryOnly = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'MMTaskbarEnabled'
            ValueType = 'DWord'
            Value = 0
        }

        # show (1, default) or hide (0) the search box on the taskbar
        $HideTaskbarSearchBox = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
            ValueName = 'SearchBoxTaskbarMode'
            ValueType = 'DWord'
            Value = 0
        }

        # show (1, default) or hide (0) the task view button on the taskbar
        $HideTaskViewButton = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ShowTaskViewButton'
            ValueType = 'DWord'
            Value = 0
        }

        # enable (1, default) or disable (0) Fast Startup
        $DisableFastStartup = @{
            KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            ValueName = 'HiberbootEnabled'
            ValueType = 'DWord'
            Value = 0
        }

        # enable (0, default) or disable (1) Shake to Minimize
        $DisallowShaking = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'DisallowShaking'
            ValueType = 'DWord'
            Value = 1
        }

        # enable (2, default) or disable (4) the Windows DNS Client DNS cache
        $DisableLocalDnsCache = @{
            KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache'
            ValueName = 'Start'
            ValueType = 'DWord'
            Value = 4
        }

        # allow (0, default) or disallow (3) Microsoft accounts on this PC
        $AllowNoConnectedUser = @{
            KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'NoConnectedUser'
            ValueType = 'DWord'
            Value = 3
        }

        # create a registry key to disable the new Windows 11 context menu
        $InprocServerOldContextMenu = @{
            KeyPath = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
            ValueName = '(Default)'
            ValueType = 'String'
            Value = ''
        }

        # disable link-local multicast name resolution (LLMNR), which forces the use of a DNS server
        $DNSClientDisableMulticastResolution = @{
            KeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMultiCast'
            ValueType = 'DWORD'
            Value = 0
        }

        # don't render window contents while dragging (displays an outline only)
        $DisableRenderWindowsWhileDragging = @{
            KeyPath = 'HKCU:\Control Panel\Desktop'
            ValueName = 'DragFullWindows'
            ValueType = 'String'
            Value = '0'
        }

        # disable font smoothing (makes fonts ugly)
        $DisableFontSmoothing = @{
            KeyPath = 'HKCU:\Control Panel\Desktop'
            ValueName = 'FontSmoothing'
            ValueType = 'String'
            Value = '0'
        }

        # disable drop shadows for desktop icon labels
        $DisableDesktopIconShadows = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ListviewShadow'
            ValueType = 'DWORD'
            Value = 0
        }

        # disable window maximize and minimize animations
        $DisableMaximizeMinimizeAnimations = @{
            KeyPath = 'HKCU:\Control Panel\Desktop\WindowMetrics'
            ValueName = 'MinAnimate'
            ValueType = 'String'
            Value = '0'
        }
        
        # disable taskbar animations
        $DisableTaskbarAnimations = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'TaskbarAnimations'
            ValueType = 'DWORD'
            Value = 0
        }

        # disable Aero Peek
        $DisableAeroPeek = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\DWM'
            ValueName = 'EnableAeroPeek'
            ValueType = 'DWORD'
            Value = 0
        }

        # not sure exactly what thumbnails this affects, but it's in the Performance dialog.
        $DisableThumbnails = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'IconsOnly'
            ValueType = 'DWORD'
            Value = 1
        }

        # disables the blue translucent rectangle thingy that's drawn when you select desktop icons
        $DisableTranslucentDesktopSelectionPreview = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ListviewAlphaSelect'
            ValueType = 'DWORD'
            Value = 0
        }

        # Set UserPreferencesMask to disable remaining Appearance features
        $DisableOtherAppearanceOptions = @{
            KeyPath = 'HKCU:\Control Panel\Desktop'
            ValueName = 'UserPreferencesMask'
            ValueType = 'Binary'
            Value = [byte[]]@(0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)
        }

        $ShowHibernatePowerMenuOption = @{
            KeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings'
            ValueName = 'ShowHibernateOption'
            ValueType = 'DWORD'
            Value = 1
        }

        $DoNotHideHibernatePowerMenuOption = @{
            KeyPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernate'
            ValueName = 'value'
            ValueType = 'DWORD'
            Value = 1
        }

        $ShowHiddenFilesCurrentUser = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'Hidden'
            ValueType = 'DWORD'
            Value = 1
        }

        $ShowFileExtensionsCurrentUser = @{
            KeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'HideFileExt'
            ValueType = 'DWORD'
            Value = 0
        }

        # boolean "tweak enabled" parameters to be used to build regkey array
        $Desired = $Configuration.Registry.Options

        # list of splatted parameters to be passed to Set-RegistryValue one at a time
        # prefer config file - if not found, default to 'performance' options
        Foreach ($RegistryValue in @(

            if (-not $Desired.TaskbarSingleMonitor) {}
            else {$ShowTaskbarPrimaryOnly}

            if (-not $Desired.TaskbarSearchBoxDisabled) {}
            else {$HideTaskbarSearchBox} 

            if (-not $Desired.TaskbarTaskViewDisabled) {}
            else {$HideTaskViewButton} 

            if (-not $Desired.FastStartupDisabled) {}
            else {$DisableFastStartup} 

            if (-not $Desired.ShakeToMinimizeDisabled) {}
            else {$DisallowShaking} 

            if (-not $Desired.DnsCacheDisabled) {}
            else {$DisableLocalDnsCache} 

            if (-not $Desired.MicrosoftAccountsDisabled) {}
            else {$AllowNoConnectedUser}

            if (-not $Desired.$NewContextMenuDisabled) {}
            else {$InprocServerOldContextMenu}

            if (-not $Desired.LLMNRDisabled) {}
            else {$DNSClientDisableMulticastResolution}

            if (-not $Desired.RenderWindowsWhileDraggingDisabled) {}
            else {$DisableRenderWindowsWhileDragging}

            if ($Desired.FontSmoothingDisabled) {$DisableFontSmoothing}
            else {} # treat this one differently because I want it enabled by default

            if (-not $Desired.DesktopIconShadowsDisabled) {}
            else {$DisableDesktopIconShadows}

            if (-not $Desired.MaximizeMinimizeAnimationsDisabled) {}
            else {$DisableMaximizeMinimizeAnimations}

            if (-not $Desired.TaskbarAnimationsDisabled) {}
            else {$DisableTaskbarAnimations}

            if (-not $Desired.AeroPeekDisabled) {}
            else {$DisableAeroPeek}

            if (-not $Desired.ThumbnailsDisabled) {}
            else {$DisableThumbnails}

            if (-not $Desired.TranslucentDesktopSelectionDisabled) {}
            else {$DisableTranslucentDesktopSelectionPreview}

            if (-not $Desired.OtherAppearanceOptionsDisabled) {}
            else {$DisableOtherAppearanceOptions}

            if (-not $Desired.ShowHibernatePowerMenuOption) {}
            else {$ShowHibernatePowerMenuOption, $DoNotHideHibernatePowerMenuOption}

            if (-not $Desired.ShowHiddenFiles) {}
            else {$ShowHiddenFilesCurrentUser}

            if (-not $Desired.ShowFileExtensions) {}
            else {$ShowFileExtensionsCurrentUser}

        )) {
        
            Set-RegistryValue @RegistryValue
            
        }

        # kill Explorer (it will restart) to apply changes immediately
        Stop-Process -Name Explorer -Force

    }

    # Windows tweaks: disable Netbios - this will only disable Netbios on adapters that are currently up
    # TODO: spawn a script on network adapter change to kill netbios?
    # (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled='true').SetTcpipNetbios(2)

    if ($Configuration.Sudo.Enabled) {

        & sudo config --enable normal

    }

    if ($Configuration.HyperV.Enabled) {

        $HyperV = $Configuration.HyperV
        
        Enable-WindowsOptionalFeature `
            -NoRestart `
            -Online `
            -FeatureName 'Microsoft-Hyper-V' `
            -All # -IncludeManagementTools

        # VMP is required for WSL - without it, first boot fails
        # probably best to just include it with Hyper-V, so we'll do that
        Enable-WindowsOptionalFeature `
            -NoRestart `
            -Online `
            -FeatureName 'VirtualMachinePlatform'

        # set VHDX and vmcfg default PATHs
        # TODO: this doesn't work until Hyper-V has been enabled & the system has been rebooted (I think)
        <#
        if ($HyperV.Config.Modify) {

            # TODO: error handling if drive or folder doesn't exist
            Set-VMHost -VirtualHardDiskPath $HyperV.Config.VhdxPath
            Set-VMHost -VirtualMachinePath $HyperV.Config.FilePath

        }
        #>

        if ($HyperV.InstallDockerCE) {

            # this reboots the computer unprompted in the middle of the script
            # thanks Microsoft
            # TODO: fix before implementing
            <#
                Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1' -o install-docker-ce.ps1
                .\install-docker-ce.ps1
            #>
        
        }

        if ($HyperV.WSL.Enabled) {
            wsl.exe `
                --install `
                -d $HyperV.WSL.Distro
        }
        
        if ($HyperV.WindowsSandbox.Enabled) {

            Write-Host('+++ Enabling Windows Sandbox +++')

            Enable-WindowsOptionalFeature `
                -FeatureName 'Containers-DisposableClientVM' `
                -Online `
                -NoRestart `
                -ErrorAction Stop

        }

    }

    if ($Configuration.Telnet.Enabled) {

        Enable-WindowsOptionalFeature `
            -FeatureName 'TelnetClient' `
            -Online `
            -NoRestart `
            -ErrorAction Stop

    }

    if ($Configuration.Software.InstallSoftware) {

        Write-Host `
            '+++ Installing applications +++'
        
        $Scoop = $Configuration.Software.Scoop
        if ($Scoop.Enabled) {
            
            Write-Host `
                '+++ pre-install for Scoop - check if it already exists +++'
        
            if ( -not [bool](Get-Command scoop)) {
        
                Write-Host `
                    '+++ Scoop not found. Installing the Scoop package manager +++'
                Invoke-Expression `
                    "& {$(Invoke-RestMethod https://get.scoop.sh)} -RunAsAdmin"
        
            } else {
                Write-Host `
                    '+++ Scoop was found. Skipping installation +++'
            }
        
            # install the Scoop packages necessary to add buckets
            Install-ScoopRange($Scoop.Packages.Dependencies)
            # add Scoop repos (buckets)
            Add-ScoopBucketRange($Scoop.Buckets)
            # install desired Scoop packages
            Install-ScoopRange($Scoop.Packages.Utilities)
            Install-ScoopRange($Scoop.Packages.Languages)
        
        } else {
            Write-Host `
                '--- Skipping installation of Scoop packages ---'
        }


        $Winget = $Configuration.Software.Winget
        # Install apps with the winget package manager
        if ($Winget.Enabled) {
            
            # we no longer care about 23H2 or older, if Winget is not installed, install it. Otherwise, use it
            if (-not (Get-Command winget) ) {
                
                Write-Host `
                    'Winget is requested and not currently installed. Installing Winget.'

                Install-Winget

                Write-Host `
                    'Winget has been installed.'

            }
        
            Write-Host `
                '+++ Beginning installation of Winget and Windows Store apps. +++'

            Install-WingetPackages $Winget.Dependencies.Packages
            
            # remove the Enabled and Dependencies pairs so it's simpler to iterate through
            $Winget.PSObject.Properties.Remove("Enabled")
            $Winget.PSObject.Properties.Remove("Dependencies")

            foreach ($Category in $Winget.PSObject.Properties) {
                if ($Category.Value.Enabled) {
                    Install-WingetPackages $Category.Value.Packages
                }
            }
        }

    } else {
        Write-Host `
            '--- Package installation bypassed ---'
    }

    if ($Configuration.Git.Enabled) {

        $Git = $Configuration.Git

        git config --global user.name "$($Git.User.Name)"

        & git config --global user.email "$($Git.User.Email)"

    }

    if ($RenameComputer) {

        $SerialNumber = (Get-CimInstance win32_bios | Select-Object SerialNumber)

        $DesiredHostname = $Machines[$SerialNumber]

        if ($DesiredHostname -and (hostname -ne $DesiredHostname) ) {

            Write-Host `
                "Computer $($SerialNumber) with hostname $(hostname) does not match desired hostname $($DesiredHostname). Renaming the machine..."
            
            Rename-Computer $DesiredHostname

        }

    }
}
END {

    Write-Host `
        "Execution completed successfully at $(Get-Date -UFormat %s) in $($Stopwatch.Elapsed.TotalSeconds) seconds."
    
    Stop-Transcript

    exit 0

}
