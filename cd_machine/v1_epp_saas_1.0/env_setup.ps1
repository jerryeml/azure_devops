[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $DefaultUsername,
    [string] $DefaultPassword,
    [string] $AzureToken="optional_input",
    [string] $AgentTags="optional_input",
    [string] $AgentPoolConfig="C:\deployment_agent\config.cmd",
    [string] $AzureDevopsProjectUrl="optional_input",
    [string] $AzureDevopsProject="optional_input",
    [string] $AzureDevopsDeployGroup="optional_input",
    [string] $action="DEFAULT",
    [string] $HostName=$env:COMPUTERNAME,
    [string] $Port="5986",
    [string] $workdir = "c:\installer\"
)
###################################################################################################
#
# PowerShell configurations
#

# NOTE: Because the $ErrorActionPreference is "Stop", this script will stop on first failure.
#       This is necessary to ensure we capture errors inside the try-catch-finally block.
$ErrorActionPreference = "Stop"

# Make download speed more faster
$ProgressPreference = "SilentlyContinue"

# Change to TLS1.2 https://somoit.net/powershell/could-not-create-ssltls-secure-channel
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure we set the working directory to that of the script.
Push-Location $PSScriptRoot


###################################################################################################
#
# Handle all errors in this script.
#

trap
{
    # NOTE: This trap will handle all errors. There should be no need to use a catch below in this
    #       script, unless you want to ignore a specific error.
    $message = $error[0].Exception.Message
    if ($message)
    {
        Write-Log $message
        Write-Output -Object "ERROR: $message" -ForegroundColor Red
    }
    
    # IMPORTANT NOTE: Throwing a terminating error (using $ErrorActionPreference = "Stop") still
    # returns exit code zero from the PowerShell script when using -File. The workaround is to
    # NOT use -File when calling this script and leverage the try-catch-finally block and return
    # a non-zero exit code from the catch block.
    exit -1
}


###################################################################################################
#
# Functions used in this script.
#


function Write-Log
{
    [CmdletBinding()]
    param (
        [string] $content,
        [string] $logFilePath="C:\installer\env_setup.log",
	    [string] $workdir = "c:\installer\"
    )

    # Check if work directory exists if not create it
    if (-not (Test-Path -Path $workdir -PathType Container))
    { 
        New-Item -Path $workdir  -ItemType directory | Out-Null
    }
    Set-Location $workdir

    Write-Host $content
    $logDateTime = Get-Date
    Add-Content $logFilePath -value "[$logDateTime] $content"
}


function handle_lastexitcode
{
    [CmdletBinding()]
    param(
    )

    if ($LASTEXITCODE -ne 0)
    {
        Write-Log "The artifact failed to apply."
        throw 'The artifact failed to apply.'
    }
}


function add_winrm_to_firewall_exception
{
    [CmdletBinding()]
    param(
        [string] $Port="5986"
    )

    $ruleName = "Allow WinRm in" # Windows Remote Management (HTTPS-In)

    # Determine if the rule already exists.
    netsh advfirewall firewall show rule name=$ruleName | Out-Null
    if ($LastExitCode -eq 0)
    {
        # Delete the existing rule.
        Write-Log "Delete the existing rule"
        netsh advfirewall firewall delete rule name=$ruleName dir=in protocol=TCP | Out-Null
        handle_lastexitcode
    }

    # Add a new firewall rule.
    Write-Log "Add a new firewall rule."
    netsh advfirewall firewall add rule name=$ruleName dir=in action=allow protocol=TCP localport=$Port | Out-Null
    handle_lastexitcode
}


function set_winrm_https_to_specify_port
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $HostName,
        [string] $Port="5986",
        [string] $workdir = "c:\installer\"
    )
    Write-Log "WinRM Prepare"
    Set-Location $workdir
    download_makecert

    Write-Log "The Host name: $($HostName) and Port: $($Port)"
    Write-Log "Add firewall exception for port $($Port)."
    add_winrm_to_firewall_exception -Port $Port

    # Ensure that the service is running and is accepting requests.
    set_network_to_private
    winrm quickconfig -force

    # The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb.
    # The small envelop size, if not changed, results in the WS-Management service responding with an error that
    # the request size exceeded the configured MaxEnvelopeSize quota.
    Write-Log 'Configuring MaxEnvelopeSize to 8192 kb.'
    winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

    Write-Log 'Configuring WinRM listener.'
    set_winrm_listener -HostName $HostName -Port $Port

    set_network_to_public
    Write-Log "Set winrm Successfully"
}


function download_makecert
{
    # Download the makecert
    $workdir = "c:\installer"
    $source = "https://raw.githubusercontent.com/jerryeml/azure_devops/master/makecert.exe"
    $destination = "$workdir\makecert.exe"
    
    if (Get-Command 'Invoke-Webrequest')
    {
        Invoke-WebRequest $source -OutFile $destination
    }
    else
    {
        $WebClient = New-Object System.Net.WebClient
        $webclient.DownloadFile($source, $destination)
    }
}


function set_network_to_private
{
    $current_network_category = Get-NetConnectionProfile
    Write-Log "Before change Network Category: $($current_network_category)"
    Set-NetConnectionProfile -NetworkCategory Private
    $after_network_category = Get-NetConnectionProfile
    Write-Log "After change Network Category: $($after_network_category)"
    Get-NetConnectionProfile -NetworkCategory Private
}


function set_network_to_public
{
    $current_network_category = Get-NetConnectionProfile
    Write-Log "Before change Network Category: $($current_network_category)"
    Set-NetConnectionProfile -NetworkCategory Public
    $after_network_category = Get-NetConnectionProfile
    Write-Log "After change Network Category: $($after_network_category)"
    Get-NetConnectionProfile -NetworkCategory Public
}


function add_new_cert
{
    [CmdletBinding()]
    param(
        [string] $HostName
    )

    # makecert ocassionally produces negative serial numbers, which golang tls/crypto small than 1.6.1 cannot handle.
	# https://github.com/golang/go/issues/8265
    $serial = Get-Random
    .\makecert.exe -r -pe -n CN=$HostName -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial 2>&1 | Out-Null

    $thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $HostName } | Select-Object -Last 1).Thumbprint

    if(-not $thumbprint)
    {
        Write-Log "Failed to create the test certificate."
        throw 'Failed to create the test certificate.'
    }

    return $thumbprint
}


function remove_winrm_listener
{
    [CmdletBinding()]
    param(
    )

    try
    {
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains('HTTPS'))
            {
                Write-Log 'HTTPS is already configured. Deleting the exisiting configuration.'
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>&1 | Out-Null
                break
            }
        }
    }
    catch
    {
        Write-Log "INFO: Exception while deleting the listener: $($_.Exception.Message)"
    }
}


function set_winrm_listener
{
    [CmdletBinding()]
    param
    (
        [string] $HostName,
        [string] $Port
    )

    # Delete the WinRM Https listener, if it is already configured.
    remove_winrm_listener

    Write-Log "Prepare to Create a test certificate"
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $HostName } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
        $thumbprint = add_new_cert -HostName $HostName
        Write-Log "Create certificate and get thumbprint: $($thumbprint)"
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped. Delete the certificate.
        Write-Log "The private key is missing - could have been sysprepped. Delete the certificate"
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force | Out-Null
        $thumbprint = add_new_cert -HostName $HostName
    }

    netsh http show sslcert ipport=0.0.0.0:$Port | Out-Null
    if ($LastExitCode -eq 1)
    {
        Write-Log "No SSL Certificate Binding"
        $WinrmCreate = "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Port=`"$Port`";Hostname=`"$HostName`";CertificateThumbprint=`"$thumbPrint`"}"
    }
    else
    {
        Write-Log "SSL Certificate Already Binding to Port:($Port)"
        $WinrmCreate = "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Port=`"$Port`";Hostname=`"$HostName`";CertificateThumbprint=`"`"}"
    }
    Write-Log "winrm create command: $($WinrmCreate)"
    invoke-expression $WinrmCreate
    handle_lastexitcode

    winrm set winrm/config/service/auth '@{Basic="true"}'
    handle_lastexitcode
}


function install_chocolatey
{
#     Set-ExecutionPolicy Unrestricted -Force
    Write-Log "install_chocolatey"
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Write-Log "Prepare to install package by choco"

    choco install python --version=3.8.5.20200721 -y
    # choco install azure-cli -y
    # choco install lockhunter -y
}


Function set_autologon
{
    [CmdletBinding()]
    Param(
        
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultUsername,

        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultPassword,

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$AutoLogonCount,

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$Script
                
    )

    Begin
    {
        # Registry path declaration
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    
    }
    
    Process
    {

        try
        {
            Write-Log "Prepare to config auto-logon setting"

            # Setting registry values
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String  
            Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String
            Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
            if($AutoLogonCount)
            {
                Write-Log "Prepare to config AutoLogonCount"
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
            }
            else
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
            }
            if($Script)
            {
                Write-Log "Prepare to run script"
                Set-ItemProperty $RegROPath "(Default)" -Value "$Script" -type String
            }
            else
            {
                Set-ItemProperty $RegROPath "(Default)" -Value "" -type String
            }        
        }

        catch
        {
            Write-Output "An error had occured $Error"
        }
    }

    End
    {
        Write-Log "End of set_autologon function"
        #End
    }
}


function handel_firewarll_rules
{
    netsh advfirewall firewall show rule name="Allow Python27" dir=in | Out-Null
    if ($LastExitCode -eq 1 )
    {
        netsh advfirewall firewall add rule name="Allow Python27" dir=in action=allow program="C:\Python27\python.exe"
    }
    netsh advfirewall firewall show rule name="Allow Python38" dir=in | Out-Null
    if ($LastExitCode -eq 1 )
    {
        netsh advfirewall firewall add rule name="Allow Python38" dir=in action=allow program="C:\Python38\python.exe"
    }
}


function download_azure_pipeline_agent
{
    # Downlaod and extract VSTS windows agent
    if ((Test-Path -Path "C:\VSTSwinAgent") -eq $false)
    {
        Write-Log "Create Folder of VSTSwinAgent"
        New-Item -Path "C:\VSTSwinAgent" -ItemType "directory" -Force
    }

    Invoke-WebRequest https://vstsagentpackage.azureedge.net/agent/2.179.0/vsts-agent-win-x64-2.179.0.zip -OutFile C:\VSTSwinAgent\agent.zip

    Expand-Archive C:\VSTSwinAgent\agent.zip -DestinationPath C:\VSTSwinAgent -Force

    Start-Sleep -s 3
}


function register_az_deployment_interactive_agent
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $UserAccount,
        [string] $UserPwd,
        [string] $AzureToken,
        [string] $AgentTags,
        [string] $AgentPoolConfig,
        [string] $AzureDevopsProjectUrl,
        [string] $AzureDevopsProject,
        [string] $AzureDevopsDeployGroup,
        [string] $AgentTagrget = ($env:computername -split "-")[0] + ($env:computername -split "-")[-1]
    )

    try
    {
        $settings = @{
            "UserAccount"= $UserAccount;
            "UserPwd"= $UserPwd;
            "AzureToken"= $AzureToken;
            "AgentTags"= $AgentTags;
            "AgentPoolConfig"= $AgentPoolConfig;
            "AzureDevopsProjectUrl"= $AzureDevopsProjectUrl;
            "AzureDevopsProject"= $AzureDevopsProject;
            "AzureDevopsDeployGroup"= $AzureDevopsDeployGroup;
            "AgentTagrget"= $AgentTagrget;
        }

        Write-Log "register_az_deployment_interactive_agent params: $settings"
        Start-Process -FilePath $AgentPoolConfig -NoNewWindow -ArgumentList "--unattended --deploymentGroup --url $AzureDevopsProjectUrl --auth pat --token $AzureToken --projectName $AzureDevopsProject --deploymentGroupName $AzureDevopsDeployGroup --agent $AgentTagrget-DG --replace --addDeploymentGroupTags --deploymentGroupTags `"$AgentTagrget, $AgentTags`" --runAsAutoLogon --windowsLogonAccount $UserAccount --windowsLogonPassword $UserPwd"

        $nid = (Get-Process cmd).id
        Write-Log "az agent install process nid: $nid"
        return $true
    }
    catch
    {
        Write-Log "[register_az_deployment_interactive_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
        throw "[register_az_deployment_interactive_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
    }
}


function remove_az_pipeline_agent
{
    [CmdletBinding()]
    param
    (
        [string] $AzureToken,
        [string] $AgentPoolConfig
    )

    Write-Log "prepare to remove az pipeline agent"
    # config.cmd remove --auth pat --token ""
    Start-Process -FilePath $AgentPoolConfig -NoNewWindow -ArgumentList "remove --auth pat --token $AzureToken"
    $nid = (Get-Process cmd).id
    Write-Log "az agent remove process nid: $nid"
    Start-Sleep -s 10
}


function landing_script
{
    Write-Log "Start to landing script"
    Invoke-WebRequest https://raw.githubusercontent.com/jerryeml/azure_devops/master/cd_machine/v1_epp_saas_1.0/env_setup.ps1 -OutFile C:\installer\env_setup.ps1
}


function disable_privacy_experience
{
    Write-Log "Disable Privacy Experience"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t "REG_DWORD" /d 1 /f
}


function install_open_ssh_on_windows
{
    param (
    [switch]$AutoStart = $true
    )

    Write-Log "install_open_ssh_on_windows"
#     Set-ExecutionPolicy RemoteSigned -scope CurrentUser

    # show notification to change execution policy:
#     if((Get-ExecutionPolicy) -gt 'RemoteSigned' -or (Get-ExecutionPolicy) -eq 'ByPass') {
#         Write-Log "PowerShell requires an execution policy of 'RemoteSigned' to Install Win32-OpenSSH."
#         Write-Log "To make this change please run:"
#         Write-Log "'Set-ExecutionPolicy RemoteSigned -scope CurrentUser'"
#         break
#     }

    Write-Log "AutoStart: $AutoStart"
    $is_64bit = [IntPtr]::size -eq 8

    #download win32 openssh
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
    $request = [System.Net.WebRequest]::Create($url)
    $request.AllowAutoRedirect = $false
    $response = $request.GetResponse()

    $filename = "OpenSSH-Win32"

    if ($is_64bit) {
        $filename = "OpenSSH-Win64"
    }

    $download_filename = $filename + ".zip"
    Write-Log  $download_filename

    # create download folder
    $download_path = "C:\Downloads"
    If(!(Test-Path $download_path))
    {
        Write-Log "Creating Download under $download_path"
        New-Item -ItemType Directory -Force -Path $download_path
    }

    $ssh_download_url = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/" + $download_filename
    
    # download installer in downlod folder
    if (!(Test-Path "C:\Downloads\$download_filename"))
    {
        Write-Log "Downloading $ssh_download_url"
        (New-Object System.Net.WebClient).DownloadFile($ssh_download_url, "C:\Downloads\$download_filename")
    }

    Write-Log "Extracting..."

    $zipfile = "C:\Downloads\$download_filename"
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [IO.Compression.ZipFile]::ExtractToDirectory($zipfile, "C:\Program Files\")

    #Rename folder name to OpenSSH
    Rename-Item "C:\Program Files\$filename" "C:\Program Files\OpenSSH"

    Write-Log "Installing..."
    $PSCommandPath = "C:\Program Files\OpenSSH\install-sshd.ps1"
    & "$PSCommandPath"

    # ensure Administrator can log in
    Write-Log "Setting Administrator user file permissions"
    New-Item -ItemType Directory -Force -Path "C:\Users\$UserName\.ssh"
    C:\Windows\System32\icacls.exe "C:\Users\$UserName" /grant "Administrator:(OI)(CI)F"
    C:\Windows\System32\icacls.exe "C:\Program Files\OpenSSH" /grant "Administrator:(OI)RX"

    # Disable firewall to allow inbound SSH connections
    # New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

    # setup sshd service to auto-start
    Set-Service sshd -StartupType Automatic

    if ($AutoStart -eq $true) {
        Start-Service "sshd"
    }

    # set home directory to c:
    Write-Log "Setting OpenSSH to be non-strict"
    $sshd_config = Get-Content "C:\ProgramData\ssh\sshd_config"
    $sshd_config = $sshd_config -replace '#ChrootDirectory none', 'ChrootDirectory c:'
    Set-Content "C:\ProgramData\ssh\sshd_config" $sshd_config
    Write-Log "Set Default Home Directory to C:\"

    # Restart-Service
    Restart-Service "sshd" 
}

###################################################################################################
#
# Main used in this script.
#
try
{
    Write-Log "================================================================================="

    if ((Test-Path -Path $workdir) -eq $false)
    {
        Write-Log "Create Folder of installer"
        New-Item -Path $workdir -ItemType "directory" -Force
    }

    Write-Log "ACTION IS $action, start to setup environment"
    set_winrm_https_to_specify_port -HostName $HostName -Port $Port -workdir $workdir
    disable_privacy_experience
    install_open_ssh_on_windows

    if ($action.ToUpper() -eq "LANDING_ONLY")
    {
        landing_script
    }
    elseif ($action.ToUpper() -eq "INSTALL_ONLY")
    {
        set_autologon -DefaultUsername $DefaultUsername -DefaultPassword $DefaultPassword
        download_azure_pipeline_agent
        register_az_deployment_interactive_agent -UserAccount $DefaultUsername -UserPwd $DefaultPassword -AzureToken $AzureToken -AgentTags $AgentTags -AgentPoolConfig $AgentPoolConfig -AzureDevopsProjectUrl $AzureDevopsProjectUrl -AzureDevopsProject $AzureDevopsProject -AzureDevopsDeployGroup $AzureDevopsDeployGroup
        install_chocolatey
        handel_firewarll_rules
    }
    elseif ($action.ToUpper() -eq "REINSTALL_DEPLOYMENT_AGENT")
    {
        remove_az_pipeline_agent -AzureToken $AzureToken -AgentPoolConfig $AgentPoolConfig
        register_az_deployment_interactive_agent -UserAccount $DefaultUsername -UserPwd $DefaultPassword -AzureToken $AzureToken -AgentTags $AgentTags -AgentPoolConfig $AgentPoolConfig -AzureDevopsProjectUrl $AzureDevopsProjectUrl -AzureDevopsProject $AzureDevopsProject -AzureDevopsDeployGroup $AzureDevopsDeployGroup
    }
    else
    {
        install_chocolatey
        handel_firewarll_rules
    }

    Write-Log 'Artifact completed successfully.'
}
finally
{
    Pop-Location
}
