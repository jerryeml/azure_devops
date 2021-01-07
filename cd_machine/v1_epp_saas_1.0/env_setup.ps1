[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $DefaultUsername,
    [securestring] $DefaultPassword,
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


function set_winrm_listener
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


function install_chocolatey
{
    Set-ExecutionPolicy Unrestricted -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install python3 -y --version=3.8.5
    choco install azure-cli -y
    choco install googlechrome -y
    # choco install lockhunter -y
}


Function set_autologon
{
    [CmdletBinding()]
    Param(
        
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultUsername,

        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [SecureString[]]$DefaultPassword,

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$AutoLogonCount,

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$Script
                
    )

    Begin
    {
        #Registry path declaration
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    
    }
    
    Process
    {

        try
        {
            #setting registry values
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String  
            Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String  
            Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
            if($AutoLogonCount)
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
            }
            else
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
            }
            if($Script)
            {
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


###################################################################################################
#
# Main used in this script.
#
try
{
    if ((Test-Path -Path $workdir) -eq $false)
    {
        Write-Log "Create Folder of installer"
        New-Item -Path $workdir -ItemType "directory" -Force
    }

    Write-Log "Start to setup environment"
    set_autologon -DefaultUsername $DefaultUsername -DefaultPassword $DefaultPassword
    set_winrm_https_to_specify_port -HostName $HostName -Port $Port -workdir $workdir
    install_chocolatey
    handel_firewarll_rules
    Write-Log 'Artifact completed successfully.'
}
finally
{
    Pop-Location
}