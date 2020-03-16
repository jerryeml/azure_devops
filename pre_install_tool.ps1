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
function Write-Log($content, $logFilePath="C:\installer\pre_install_tool.log")
{
    Write-Host $content
    $logDateTime = Get-Date
    Add-Content $logFilePath -value "[$logDateTime] $content"
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
    # Start-Sleep -s 30
    Expand-Archive C:\VSTSwinAgent\agent.zip -DestinationPath C:\VSTSwinAgent -Force

    Invoke-WebRequest https://raw.githubusercontent.com/jerryeml/azure_devops/master/register_az_deployment_agent.ps1 -OutFile C:\installer\register_az_deployment_agent.ps1
}


function install_chocolatey
{
    Set-ExecutionPolicy Unrestricted -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install python3 -y --version=3.7.4
    # choco install python3 -y --version=3.8.1
}


###################################################################################################
#
# Main used in this script.
#
try
{
    Write-Log "Ready to Start !!!"
    install_staf_framework
    download_azure_pipeline_agent
    install_chocolatey
}
finally
{
    Pop-Location
}
