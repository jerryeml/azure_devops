[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $az_devops_org_url,
    [string] $token,
    [string] $pool_name,
    [string] $win_login_account,
    [string] $win_login_pwd,
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
        [string] $logFilePath="C:\installer\environment_setup.log",
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



function New-Certificate
{
    [CmdletBinding()]
    param(
        [string] $HostName
    )

    # makecert ocassionally produces negative serial numbers, which golang tls/crypto < 1.6.1 cannot handle.
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

function Remove-WinRMListener
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

function Set-WinRMListener
{
    [CmdletBinding()]
    param
    (
        [string] $HostName,
        [string] $Port
    )

    # Delete the WinRM Https listener, if it is already configured.
    Remove-WinRMListener

    Write-Log "Prepare to Create a test certificate"
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $HostName } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
        $thumbprint = New-Certificate -HostName $HostName
        Write-Log "Create certificate and get thumbprint: $($thumbprint)"
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped. Delete the certificate.
        Write-Log "The private key is missing - could have been sysprepped. Delete the certificate"
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force | Out-Null
        $thumbprint = New-Certificate -HostName $HostName
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

function Add-FirewallException
{
    [CmdletBinding()]
    param(
        [string] $Port
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
    Add-FirewallException -Port $Port

    # Ensure that the service is running and is accepting requests.
    set_network_to_private
    winrm quickconfig -force

    # The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb.
    # The small envelop size, if not changed, results in the WS-Management service responding with an error that
    # the request size exceeded the configured MaxEnvelopeSize quota.
    Write-Log 'Configuring MaxEnvelopeSize to 8192 kb.'
    winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

    Write-Log 'Configuring WinRM listener.'
    Set-WinRMListener -HostName $HostName -Port $Port

    set_network_to_public
    Write-Log "Set winrm Successfully"
}

function install_staf_framework 
{
    netsh advfirewall firewall add rule name="Allow STAF" dir=in action=allow protocol=Any program="C:\staf\bin\stafproc.exe" | Out-Null
    $is_staf_process_exist = Get-Process stafproc -ErrorAction SilentlyContinue
    if ($is_staf_process_exist) 
    {
        Write-Log "STAF Exists!"
    }
    else
    {
        Write-Log "Need to install STAF"
    }
}


function install_azure_pipeline_agent
{
    param
    (
        [string] $az_devops_org_url,
        [string] $token,
        [string] $pool_name,
        [string] $win_login_account,
        [string] $win_login_pwd,
        [int] $az_agent_count=7
    )
    # Downlaod and extract az pipeline windows agent
    if ((Test-Path -Path "C:\installer") -eq $false)
    {
        Write-Log "Create Folder of installer"
        New-Item -Path "C:\installer" -ItemType "directory" -Force
    }

    Invoke-WebRequest https://vstsagentpackage.azureedge.net/agent/2.179.0/vsts-agent-win-x64-2.179.0.zip -OutFile C:\installer\agent.zip

    for ($i = 0; $i -lt $az_agent_count; $i++) {
        $agent_folder = "AGENT-$i"
        $agent_installer_path = Join-Path "C:" -ChildPath $agent_folder
        Write-Host "Save to $agent_installer_path"
        Expand-Archive C:\installer\agent.zip -DestinationPath $agent_installer_path -Force

        $config_cmd_path = Join-Path $agent_installer_path -ChildPath "config.cmd"
        register_to_ci_agent - config_cmd_path $config_cmd_path -az_devops_org_url $az_devops_org_url -token $token -pool_name $pool_name -win_login_account $win_login_account -win_login_pwd $win_login_pwd
    }
}


function install_chocolatey
{
    Set-ExecutionPolicy Unrestricted -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install googlechrome -y
    choco install 7zip.install -y
    choco install notepadplusplus.install -y
    choco install git.install -y
    # choco install autoit.install -y
    choco install azure-cli -y
    # choco install azure-pipelines-agent -y
    # choco install microsoftazurestorageexplorer -y
    choco install procexp -y
    choco install procmon -y
    # choco install selenium -y
    # choco install selenium-chrome-driver -y
    # choco install vscode -y
    # choco install chocolatey-vscode -y
    # choco install vscode-ansible -y
    # choco install vscode-yaml -y
    # choco install vscode-python -y
    # choco install vscode-azure-deploy -y
    choco install sql-server-management-studio -y
    # choco install sysinternals -y
    # choco install winmerge -y 
    # choco install postman -y
    choco install wireshark -y
    choco install python --version=3.8.5.20200721 -y

    # choco install lockhunter -y
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


function register_to_ci_agent
{
    <#
        .Description
        Register Pipeline agent to from azure pipeline line to azure agent pool     
    #>
    [CmdletBinding()]
    param 
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $config_cmd_path,
        [string] $az_devops_org_url,
        [string] $token,
        [string] $pool_name,
        [string] $win_login_account,
        [string] $win_login_pwd
    )

    try
    {
        $random_string = -join ((48..57) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
        $agent_name = $env:COMPUTERNAME + "-" + $random_string

        Start-Process -FilePath $config_cmd_path -NoNewWindow -ArgumentList "--unattended --url $az_devops_org_url --auth pat --token $token --pool $pool_name --agent $agent_name --runAsService --windowsLogonAccount $win_login_account --windowsLogonPassword $win_login_pwd --replace"
        $nid = (Get-Process cmd).id
        Wait-Process -Id $nid
        return $true
    }

    catch
    {
        throw "[register_to_ci_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
    }

}


###################################################################################################
#
# Main used in this script.
#
try
{
    # Write-Log "Prepare to installl packages"
    install_azure_pipeline_agent -az_devops_org_url $az_devops_org_url -token $token -pool_name $pool_name -win_login_account $win_login_account -win_login_pwd $win_login_pwd,
    # set_winrm_https_to_specify_port -HostName $HostName -Port $Port -workdir $workdir
    # install_staf_framework
    # install_chocolatey
    # handel_firewarll_rules
    # Write-Log 'Artifact completed successfully.'
}
finally
{
    Pop-Location
}
