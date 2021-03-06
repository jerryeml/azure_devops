param
(
	########################################################
    ## Parameter
    [string] $azure_devops_pat,
    [string] $key,
    [string] $value,
    [string] $SCRIPT_LOG_ZIP_NAME = ("{0}_GoodBuildDebug" -f $env:computername),
	[string] $sub_folder_path = "executable\\one"
)

# Import Apex One Family params as $global_params
$SplitTempPath = $PSScriptRoot -split $sub_folder_path
$gb_common_function_script = Join-Path -Path $SplitTempPath[0] -ChildPath "common\\common_util.psm1"
Import-Module -Name $gb_common_function_script -Force -Verbose

debug_log_title

# execution function
create_debug_log @{Message = "Loading update_params_to_variable_group"; FileName = log_file_name{}; LineNumber = line_number{}}
$result = update_params_to_variable_group -azure_devops_pat $azure_devops_pat -vg_id $global_params.azure_vg_one_id -key $key -value $value


# maintenance of logging
create_debug_log @{Message = "Good Build DebugLog Maintenance."; FileName = log_file_name{}; LineNumber = line_number{}}
debug_log_maintenance -ZipName $SCRIPT_LOG_ZIP_NAME

if ($result -eq $false)
{
    exit 1
}