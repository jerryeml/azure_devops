param
(
	########################################################
    ## Parameter
    # [string] $azure_devops_pat,
    # [string] $env_type_and_product,
    # [string] $env = $env_type_and_product.split('-')[0],
    # [string] $product = $env_type_and_product.split('-')[1],
    [string] $SCRIPT_LOG_ZIP_NAME = ("{0}_GoodBuildDebug" -f $env:computername),
	[string] $sub_folder_path = "executable"
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
Write-Host "##vso[task.setvariable variable=vm_prefix]$vm_prefix_name"

create_debug_log @{Message = "Loading generate_expiration_date"; FileName = log_file_name{}; LineNumber = line_number{}}
$expiration_date = generate_expiration_date
create_debug_log @{Message = "expiration_date: $($expiration_date)"; FileName = log_file_name{}; LineNumber = line_number{}}
Write-Host "##vso[task.setvariable variable=expiration_date]$expiration_date"

# maintenance of logging
create_debug_log @{Message = "Good Build DebugLog Maintenance."; FileName = log_file_name{}; LineNumber = line_number{}}
debug_log_maintenance -ZipName $SCRIPT_LOG_ZIP_NAME
