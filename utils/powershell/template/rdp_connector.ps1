# reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "PrivacyConsentStatus" /t "REG_DWORD" /d 1 /f
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t "REG_DWORD" /d 1 /f

Write-Output "Connecting to $Server"
$Server="10.140.48.44"
$User="trend"
$Password="Osce@1234"
cmdkey /generic:TERMSRV/$Server /user:$User /pass:$Password
mstsc /v:$Server