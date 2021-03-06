<#
    .Description
    Register Pipeline agent to from azure pipeline line to azure agent pool     
#>
[CmdletBinding()]
param 
(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $UserAccount,
    [string] $UserPwd,
    [string] $AzureToken,
    [string] $Platform,
    [string] $AgentPoolConfig,
    [string] $AzureDevopsProjectUrl,
    [string] $AzureDevopsProject,
    [string] $AzureDevopsDeployGroup,
    [string] $AgentTagrget = $env:computername,
    [string] $DeploymentTag = $AgentTagrget.Replace("-vm", ""),
    [string] $GroupTag = $AgentTagrget.Split("-")[-1]
)
try
{
    Start-Process -FilePath $AgentPoolConfig -NoNewWindow -ArgumentList "--unattended --deploymentGroup --url $AzureDevopsProjectUrl --auth pat --token $AzureToken --projectName $AzureDevopsProject --deploymentGroupName $AzureDevopsDeployGroup --agent $AgentTagrget-DG --replace --addDeploymentGroupTags --deploymentGroupTags `"$Platform, $DeploymentTag, $GroupTag`" --runAsAutoLogon --windowsLogonAccount $UserAccount --windowsLogonPassword $UserPwd --noRestart"
    $nid = (Get-Process cmd).id
    Wait-Process -Id $nid
    return $true
}
catch
{
    throw "[register_az_deployment_agent][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
}
