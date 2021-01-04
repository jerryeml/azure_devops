Param ([string]$ForceOverwrite = 'N')

$taskName = "task_name"
$taskPath = "maintenance"
$ErrorActionPreference = "STOP"
$chkExist = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName -and $_.TaskPath -eq "\$taskPath\" }

if ($chkExist) {
    if ($ForceOverwrite -eq 'Y' -or $(Read-Host "[$taskName] already exists，delete it? (Y/N)").ToUpper() -eq 'Y') {
        Unregister-ScheduledTask $taskName -Confirm:$false 
    }
    else {
        Write-Host "abort to add this task" -ForegroundColor Red
        Exit 
    }
}

# execution section
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument '-NoProfile -ExecutionPolicy ByPass -WindowStyle Hidden -Command "C:\Users\trend\Desktop\clean_log_folder.ps1" '
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 3 -At 12am
Register-ScheduledTask $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -User "trend" -Password "Osce@1234$"