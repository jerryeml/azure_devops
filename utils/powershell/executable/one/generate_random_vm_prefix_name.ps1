param
(
	########################################################
    ## Parameter
    [string] $azure_devops_pat,
    [string] $product = "one",
    [string] $SCRIPT_LOG_ZIP_NAME = ("{0}_GoodBuildDebug" -f $env:computername),
	[string] $sub_folder_path = "executable\\one"
)

# Import Apex One Family params as $global_params
$SplitTempPath = $PSScriptRoot -split $sub_folder_path
$gb_common_function_script = Join-Path -Path $SplitTempPath[0] -ChildPath "common\\common_util.psm1"
Import-Module -Name $gb_common_function_script -Force -Verbose

debug_log_title

# execution function
create_debug_log @{Message = "Loading generate_random_vm_prefix_name"; FileName = log_file_name{}; LineNumber = line_number{}}
$vm_prefix_name = generate_random_vm_prefix_name
create_debug_log @{Message = "vm_prefix_name: $($vm_prefix_name)"; FileName = log_file_name{}; LineNumber = line_number{}}

# Naming example 
# product10-prefix-count / product16-prefix-count
$vm10_prefix = $product + "-10" + $vm_prefix_name
$vm16_prefix = $product + "-16" + $vm_prefix_name
create_debug_log @{Message = "vm_prefix_name: $($vm10_prefix) / $($vm16_prefix)"; FileName = log_file_name{}; LineNumber = line_number{}}

create_debug_log @{Message = "Loading update_params_to_variable_group"; FileName = log_file_name{}; LineNumber = line_number{}}
$result = update_params_to_variable_group -azure_devops_pat $azure_devops_pat -vg_id $global_params.azure_vg_one_id -key "vm10_prefix" -value $vm10_prefix
$result = update_params_to_variable_group -azure_devops_pat $azure_devops_pat -vg_id $global_params.azure_vg_one_id -key "vm16_prefix" -value $vm16_prefix


# maintenance of logging
create_debug_log @{Message = "Good Build DebugLog Maintenance."; FileName = log_file_name{}; LineNumber = line_number{}}
debug_log_maintenance -ZipName $SCRIPT_LOG_ZIP_NAME

if ($result -ne $true)
{
    exit 1
}