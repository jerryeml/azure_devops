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


$logFilePath="C:\installer\log_"+$executeDateFormat+".log"

function Write-Log($content)
{
	Write-Debug $content
    $logDateTime=Get-Date
	Add-Content $logFilePath -value "[$logDateTime] $content"
}

Write-Log "Hello World!!!"

# Install STAF
netsh advfirewall firewall add rule name="Allow STAF" dir=in action=allow protocol=Any program="C:\staf\bin\stafproc.exe" | Out-Null

# Downlaod and extract VSTS windows agent
mkdir C:\VSTSwinAgent ;
Invoke-WebRequest https://vstsagentpackage.azureedge.net/agent/2.165.1/vsts-agent-win-x64-2.165.1.zip -OutFile C:\VSTSwinAgent\agent.zip
#Start-Sleep -s 30
Expand-Archive C:\VSTSwinAgent\agent.zip -DestinationPath C:\VSTSwinAgent

#Set Execution Policy
Set-ExecutionPolicy Unrestricted -Force

#====================================================================
# Chocolaty install
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
