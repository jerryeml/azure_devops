function change_az_agent_to_interactive_mode()
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
	    [string] $AgentTagrget,
	    [string] $UserAccount,
	    [string] $UserPwd,
        [string] $AzureToken,
        [string] $Platform,
	    [string] $AgentPoolConfig,
	    [string] $AzureDevopsProjectUrl,
	    [string] $AzureDevopsProject,
        [string] $AzureDevopsDeployGroup,
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
        throw "[change_az_agent_to_interactive_mode][$($AgentTagrget)] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
    }
}

change_az_agent_to_interactive_mode