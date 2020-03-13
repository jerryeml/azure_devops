[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [string] $HostName,
    [string] $Port=5986
)

###################################################################################################
#
# PowerShell configurations
#

# NOTE: Because the $ErrorActionPreference is "Stop", this script will stop on first failure.
#       This is necessary to ensure we capture errors inside the try-catch-finally block.
$ErrorActionPreference = "Stop"

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
        Write-Host -Object "ERROR: $message" -ForegroundColor Red
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

function Handle-LastExitCode
{
    [CmdletBinding()]
    param(
    )

    if ($LASTEXITCODE -ne 0)
    {
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
    cd $workdir
    .\makecert.exe -r -pe -n CN=$HostName -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial 2>&1 | Out-Null

    $thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $HostName } | Select-Object -Last 1).Thumbprint

    if(-not $thumbprint)
    {
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
                Write-Output 'HTTPS is already configured. Deleting the exisiting configuration.'
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>&1 | Out-Null
                break
            }
        }
    }
    catch
    {
        Write-Output "INFO: Exception while deleting the listener: $($_.Exception.Message)"
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

    # Create a test certificate.
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $HostName } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
	    $thumbprint = New-Certificate -HostName $HostName
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped. Delete the certificate.
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force | Out-Null
        $thumbprint = New-Certificate -HostName $HostName
    }

    $WinrmCreate = "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Port=`"$Port`";Hostname=`"$HostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    Handle-LastExitCode

    winrm set winrm/config/service/auth '@{Basic="true"}'
    Handle-LastExitCode
}

function Add-FirewallException
{
    [CmdletBinding()]
    param(
        [string] $Port
    )

    $ruleName = "Windows Remote Management (HTTPS-In)"

    # Determine if the rule already exists.
    netsh advfirewall firewall show rule name=$ruleName | Out-Null
    if ($LastExitCode -eq 0)
    {
        # Delete the existing rule.
        netsh advfirewall firewall delete rule name=$ruleName dir=in protocol=TCP localport=$Port | Out-Null
        Handle-LastExitCode
    }

    # Add a new firewall rule.
    netsh advfirewall firewall add rule name=$ruleName dir=in action=allow protocol=TCP localport=$Port | Out-Null
    Handle-LastExitCode
}

try {
    # Path for the workdir
    $workdir = "c:\installer\"

    # Check if work directory exists if not create it

    if (Test-Path -Path $workdir -PathType Container)
    { 
        Write-Host "$workdir already exists" -ForegroundColor Red
    }
    else
    {
        New-Item -Path $workdir  -ItemType directory
    }

    # Download the makecert
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

    Write-Output 'Add firewall exception for port 5986.'
    Add-FirewallException -Port $Port

    # Ensure that the service is running and is accepting requests.
    winrm quickconfig -force

    # The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb.
    # The small envelop size, if not changed, results in the WS-Management service responding with an error that
    # the request size exceeded the configured MaxEnvelopeSize quota.
    Write-Output 'Configuring MaxEnvelopeSize to 8192 kb.'
    winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

    Write-Output 'Configuring WinRM listener.'
    Set-WinRMListener -HostName $HostName -Port $Port

    Write-Output 'Artifact completed successfully.'
}
finally {
    Pop-Location
}
