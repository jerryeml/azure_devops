[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $UserAccount,
    [string] $UserPwd,
    [string] $AzureToken,
    [string] $AgentTags,
    [string] $AgentPoolConfig,
    [string] $AzureDevopsProjectUrl,
    [string] $AzureDevopsProject,
    [string] $AzureDevopsDeployGroup,
    [string] $AgentTagrget = $env:computername,
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
        [string] $logFilePath="C:\installer\pre_install_tool.log",
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


function Add-FirewallException
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


function download_azure_pipeline_agent
{
    # Downlaod and extract VSTS windows agent
    if ((Test-Path -Path "C:\VSTSwinAgent") -eq $false)
    {
        Write-Log "Create Folder of VSTSwinAgent"
        New-Item -Path "C:\VSTSwinAgent" -ItemType "directory" -Force
    }

    Invoke-WebRequest https://vstsagentpackage.azureedge.net/agent/2.165.1/vsts-agent-win-x64-2.165.1.zip -OutFile C:\VSTSwinAgent\agent.zip

    Expand-Archive C:\VSTSwinAgent\agent.zip -DestinationPath C:\VSTSwinAgent -Force

    Invoke-WebRequest https://raw.githubusercontent.com/jerryeml/azure_devops/master/register_az_deployment_agent.ps1 -OutFile C:\installer\register_az_deployment_agent.ps1

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
        [string] $AgentTagrget = $env:computername
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

        Write-Log "params: $settings"
        Start-Process -FilePath $AgentPoolConfig -NoNewWindow -ArgumentList "--unattended --deploymentGroup --url $AzureDevopsProjectUrl --auth pat --token $AzureToken --projectName $AzureDevopsProject --deploymentGroupName $AzureDevopsDeployGroup --agent $AgentTagrget-DG --replace --addDeploymentGroupTags --deploymentGroupTags `"$AgentTagrget, $AgentTags`" --runAsAutoLogon --windowsLogonAccount $UserAccount --windowsLogonPassword $UserPwd --noRestart"

        $nid = (Get-Process cmd).id
        Write-Log "az agent install process nid: $nid"
        # Wait-Process -Id $nid
        Write-Log "az agent install complete"
        return $true
    }
    catch
    {
        Write-Log "[register_az_deployment_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
        throw "[register_az_deployment_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
    }
}

function install_chocolatey
{
    Set-ExecutionPolicy Unrestricted -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    # choco install python3 -y --version=3.7.4
    choco install python3 -y --version=3.8.1
    choco install googlechrome -y
    # choco install lockhunter -y
}


function handel_firewarll_rules
{
    # For WinRm
    Add-FirewallException

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
    Write-Log "Prepare to installl packages"
    download_azure_pipeline_agent
    register_az_deployment_interactive_agent -UserAccount $UserAccount -UserPwd $UserPwd -AzureToken $AzureToken -AgentTags $AgentTags -AgentPoolConfig $AgentPoolConfig -AzureDevopsProjectUrl $AzureDevopsProjectUrl -AzureDevopsProject $AzureDevopsProject -AzureDevopsDeployGroup $AzureDevopsDeployGroup
    install_staf_framework
    install_chocolatey
    handel_firewarll_rules
    Write-Log 'Artifact completed successfully.'
}
finally
{
    Pop-Location
}