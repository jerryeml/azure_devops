param
(
	########################################################
    ## Parameter
    [string] $SCRIPT_LOG_ZIP_NAME = ("{0}_GoodBuildDebug" -f $env:computername),
	[string] $current_folder_name = "template"
)

# Import Apex One Family params as $global_params
$SplitTempPath = $PSScriptRoot -split $current_folder_name
$gb_common_function_script = Join-Path -Path $SplitTempPath[0] -ChildPath "common\\common_util.psm1"
Import-Module -Name $gb_common_function_script -Force

debug_log_title

# execution function


# maintenance of logging
create_gb_debug_log @{Message = "Good Build DebugLog Maintenance."; FileName = log_file_name{}; LineNumber = line_number{}}
debug_log_maintenance -ZipName $SCRIPT_LOG_ZIP_NAME

if ($result -eq $false)
{
    exit 1
}