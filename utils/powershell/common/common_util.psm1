param
(
	########################################################
	## Script Parameter
	[string] $SCRIPT_Common_FOLDER_NAME = "common",
	[string] $SCRIPT_GLOBAL_PARAMS_INI = "global_params.ini",
	[string] $SCRIPT_GLOBAL_PARAM_TABLE = "global_params",
	[string] $debug_log_module = (Join-Path -Path $PSScriptRoot -ChildPath "logger.psm1")
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


###################################################################################################
#
# PowerShell init function section
#


function init()
{
	<#
        .Description
            Apex Family Script Initialization 

		.Procedure
			1. Creating Message Table	     
	#>

	[CmdletBinding()]
	Param
    (
        [parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string] $RootPath
	)

	create_debug_log @{Message = "[init] PARAM INI RootPath : ($RootPath)."; FileName = log_file_name{}; LineNumber = line_number{}}
	$Result_CreateMessageTable = create_message_table -RootPath $RootPath

	if ($Result_CreateMessageTable -ne $true) 
	{
		create_debug_log @{Message = "[init] initialization failed."; FileName = log_file_name{}; LineNumber = line_number{}}
		exit 1
	}

	create_debug_log @{Message = "[init] initialization successfully"; FileName = log_file_name{}; LineNumber = line_number{}}
	exit 0
}


function create_message_table()
{  
	<#
        .Description
            Creating Message Tables       
    #>

	[CmdletBinding()]
	Param
    (
        [parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string] $RootPath
    )

	$Path_OSCE_SaaS_Params = Join-Path -Path $RootPath -ChildPath $SCRIPT_GLOBAL_PARAMS_INI

	#############################################################
	## Creating Global Params HashTable.
	$TempParamTable = @{}
	$Result_CreateParamTable = create_hash_table -MessageFile $Path_OSCE_SaaS_Params -HashTable ([ref] $TempParamTable)

	if ($Result_CreateParamTable -ne $true)
	{
		return $Result_CreateParamTable 	
	}
	else
	{
		$Result_SetVariable = Set-Variable -Name $SCRIPT_GLOBAL_PARAM_TABLE -Scope Global -Value $TempParamTable -Force -Option ReadOnly -WarningAction SilentlyContinue -ErrorAction silentlyContinue
		create_debug_log @{Message = "[create_message_table] Creating Global Parameter Table success. return: $($Result_SetVariable)"; FileName = log_file_name{}; LineNumber = line_number{}}
	}

	return $true
}


function create_hash_table()
{   
	<#
        .Description
            Convert the file contents to hashtable       
    #>

	[CmdletBinding()]
	Param
    (
        [parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string] $MessageFile,

		[parameter(Mandatory=$true)]
        [ref] $HashTable
    )

	if ((Test-Path -Path $MessageFile) -eq $false)
	{
		create_debug_log @{Message = "[create_hash_table] ($MessageFile) does not exist. <<<"; FileName = log_file_name{}; LineNumber = line_number{}}
		return $false
	}
	else
	{
		create_debug_log @{Message = "[create_hash_table] The target message file is ($MessageFile)."; FileName = log_file_name{}; LineNumber = line_number{}}

		try
		{
			## Creating Hash Table 
			$HashTable.Value = Get-Content -Path $MessageFile | ConvertFrom-StringData
			$ElementCount = $HashTable.Value.count
			create_debug_log @{Message = "[create_hash_table] Counts ($ElementCount)."; FileName = log_file_name{}; LineNumber = line_number{}}

			if ($ElementCount -le 0)
			{
				create_debug_log @{Message = "[ERROR] The HashTable is empty."; FileName = log_file_name{}; LineNumber = line_number{}}
				exit 1
			}
			return $true
		}
		catch
		{
			create_debug_log @{Message = "[create_hash_table] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"; FileName = log_file_name{}; LineNumber = line_number{}}
			exit 1
		}
	}
}


function does_command_exitcode_success()
{
	param
	(
		[bool] $fail_with_throw = $false
	)

	if ($LASTEXITCODE -ne 0 -And $fail_with_throw -eq $true)
	{
		Write-Host "exit code actual: $($LASTEXITCODE) not 0, throw \n"
		throw
	}
	elseif ($LASTEXITCODE -ne 0)
	{
		Write-Host "exit code actual: $($LASTEXITCODE) not 0, return false \n"
		return $false
	}
	else
	{
		return $true
	}
}


###################################################################################################
#
# PowerShell common function section
#


function trigger_az_release
{
	param
	(
		[string] $rg,
		[string] $lab_name
	)

	<#
    .Description
        Using az-cli to get info of vms
	#>

}


function update_params_to_variable_group
{
	<#
		.Description
			update or add new variable to azure variable group
	#>
	param
	(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string] $azure_devops_pat,
		[string] $vg_id,
		[string] $key,
		[string] $value
	)

	# Config environment
	az extension add --name azure-devops
	Write-Output $azure_devops_pat > az_pat.txt
	Get-Content az_pat.txt | az devops login
	Remove-Item az_pat.txt
	try
	{
		az pipelines variable-group variable update --org $global_params.azure_devops_org_url --project $global_params.azure_devops_project_name --id $vg_id --name $key --value $value
		$result = does_command_exitcode_success
		if ($result -eq $false)
		{
			create_debug_log @{Message = "Update failed, use create command again"; FileName = log_file_name{}; LineNumber = line_number{}}
			az pipelines variable-group variable create --org $global_params.azure_devops_org_url --project $global_params.azure_devops_project_name --id $vg_id --name $key --value $value
			does_command_exitcode_success -fail_with_throw $true
		}
	}
	catch
	{
		Write-Verbose "An exception was caught: $($_.Exception.Message)"
		$_.Exception.Response
		create_debug_log @{Message = "Update and Create failed, $($_.Exception.Response)"; FileName = log_file_name{}; LineNumber = line_number{}}
		throw
	}
	return $true
}


function generate_random_vm_prefix_name
{
	<#
	.DESCRIPTION
	Generating random vm name in DTL
	#>

	$random_string = -join ((48..57) + (97..122) | Get-Random -Count 3 | ForEach-Object {[char]$_})
	$vm_prefix_name = $random_string
	return $vm_prefix_name
	
}


###################################################################################################
#
# PowerShell main init section
#


Import-Module -Name $debug_log_module -Force

$SplitTempPath = $PSScriptRoot -split $SCRIPT_Common_FOLDER_NAME
$GBRootPath = $SplitTempPath[0]
init -RootPath $GBRootPath
create_debug_log @{Message = "[common_function] Init Function Successfully."; FileName = log_file_name{}; LineNumber = line_number{}}
