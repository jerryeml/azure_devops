<#    
    .Description   
		Common Util Framework LogServer                
#>


param
(
	[string] $SCRIPT_LOG_TITLE = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Function Start @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
    [string] $SCRIPT_LOG_NAME = ("{0}_common_util.log" -f $env:computername),
	[string] $SCRIPT_LOG_FOLDER_PATH = ("C:\v1_epp_logs"), 
    [string] $SCRIPT_LOG_SIZE = "10MB",
	[int] $SCRIPT_KEEP_ARCHIEVE_COUNT = 10,

	## Debug Tag
	[string] $SCRIPT_DEBUG_TAG = "common_util_debug"
)


function line_number() 
{ 
    return $MyInvocation.ScriptLineNumber 
}


function log_file_name() 
{ 
    return $MyInvocation.ScriptName 
}


function get_debug_path()
{
        <#
        .Description
            Get Debug Path                 
        #>
     	
	## Set Debug Log Path
	$LogFolder = "C:\"
	if (Test-Path -Path $SCRIPT_LOG_FOLDER_PATH)
	{
		$LogFolder = $SCRIPT_LOG_FOLDER_PATH
    }
    else 
    {
		$LogFolderName = $SCRIPT_LOG_FOLDER_PATH -split "\\"
        New-Item -Path $LogFolder -Name $LogFolderName[-1] -ItemType "directory"
        $LogFolder = $SCRIPT_LOG_FOLDER_PATH
    }

	$LogPath = Join-Path -Path $LogFolder -ChildPath $SCRIPT_LOG_NAME

	return $LogPath
}


function debug_log_title()
{
        <#
        .Description
            Write the title of debug log

		.Output path
            Default path = "C:\<HostName>_GBDebug.log" or user defined path                             
        #>

	[CmdletBinding()]    
	Param
    (
        [parameter(Mandatory=$false)]
        [string] $LogPath
    )

	if ([string]::IsNullOrEmpty($LogPath))
	{
		$LogPath = get_debug_path{}
	}
	try
	{
		$Result_OutputMessage = Out-File -FilePath $LogPath -Append -InputObject $SCRIPT_LOG_TITLE -ErrorAction silentlyContinue
	}
	catch
	{
		Switch -Regex ($_.exception) {
			"used by another process" {
				Write-Host "Expection: $($_.exception)"
				Start-Sleep -s 1
				$Result_OutputMessage
			}
		}
	}
}


function debug_log_maintenance()
{
        <#
        .Description
            DebugLog Maintenance                    
        #>
     
	[CmdletBinding()]    
	Param
    (
        [parameter(Mandatory=$false)]
        [string] $LogPath,

		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string] $ZipName
    )

	if ([string]::IsNullOrEmpty($LogPath))
	{
		$LogPath = get_debug_path{}
	}

	if (Test-Path -Path $LogPath)
	{
		## Get Parent path of log 
		$Log_Parent = Split-Path -Path $LogPath -Parent 
		create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] SaaS DebugLog Parent Path ($Log_Parent)."; FileName = log_file_name{}; LineNumber = line_number{}}

		## Archieve Log
		if ((Get-item -Path $LogPath).Length -gt $SCRIPT_LOG_SIZE)
		{						
			$Log_LeafBase = [System.IO.Path]::GetFileNameWithoutExtension($LogPath) 

			$NewLogPath = Join-Path -Path $Log_Parent -ChildPath ("{0}_{1}.log" -f $Log_LeafBase, (Get-Date).tostring("yyyyMMddhhmmss"))
			$ArchivePath = Join-Path -Path $Log_Parent -ChildPath ("{0}_{1}.zip" -f $ZipName, (Get-Date).tostring("yyyyMMddhhmmss"))

			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] SaaS DebugLog Path ($LogPath)."; FileName = log_file_name{}; LineNumber = line_number{}}
			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] The size of SaaS Debuglog is greater than ($SCRIPT_LOG_SIZE)."; FileName = log_file_name{}; LineNumber = line_number{}}
			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] Starting to archieve DebugLog. ArchieveName ($ArchivePath)."; FileName = log_file_name{}; LineNumber = line_number{}}

			# Rename Log for Archive 
			$Result_Rename = Rename-Item -Path $LogPath -NewName ("{0}_{1}.log" -f $Log_LeafBase, (Get-Date).tostring("yyyyMMddhhmmss"))

			#Archive Log
			$Result_Zip = OFCUTIL-ArchiveFile -FolderPath $NewLogPath -DestPath $ArchivePath	

			if ($Result_Zip)
			{
				$Result_Remove = Remove-Item -Path $NewLogPath -Force -WarningAction SilentlyContinue -ErrorAction silentlyContinue
			}
			else
			{
				create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] Archieve DebugLog failed. Trying to archieve the file in next time."; FileName = log_file_name{}; LineNumber = line_number{}}
			}
		}
		else
		{
			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] The size of SaaS Debuglog is not greater than ($SCRIPT_LOG_SIZE). Checking the debug log size in next time."; FileName = log_file_name{}; LineNumber = line_number{}}
		}

		## Purge Log Archieve
		$Archives = Get-ChildItem -Path ("{0}\*" -f $Log_Parent) -Include ("{0}*" -f $ZipName)
		if ($Archives.Count -gt $SCRIPT_KEEP_ARCHIEVE_COUNT)
		{
			$PurgeCount = $Archives.Count - $SCRIPT_KEEP_ARCHIEVE_COUNT
			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] Archieve count ({0})." -f $Archives.Count; FileName =log_file_name{}; LineNumber = line_number{}}
			create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] Need to purge ($PurgeCount)."; FileName = log_file_name{}; LineNumber = line_number{}}

			for ($i=0; $i -lt $PurgeCount; $i++)
			{
				$PurgeTarget = Join-Path -Path $Log_Parent -ChildPath $Archives[$i].Name
				create_debug_log @{Message = "[$SCRIPT_DEBUG_TAG] Purge ($PurgeTarget)."; FileName = log_file_name{}; LineNumber = line_number{}}	
				$Result_Remove = Remove-Item -Path $PurgeTarget -Force -WarningAction SilentlyContinue -ErrorAction silentlyContinue
			}
		}
	}		
}


function create_debug_log()
{
        <#
        .Description
            Write debug log 
            
        .Output path
            Default path = "C:\<HostName>_ofcSaaSDebug.log" or user defined path 
            
        .Message format
            [Date] [Debug Info] [Script Name] [Line Number]               
        #>

	[CmdletBinding()]
	Param
    (
        [parameter(Mandatory=$true)]
        [hashtable] $DebugLog
    )

	if ($DebugLog.Count -gt 0)
	{
		try
		{
			## Check if user defined log path 
			if (($DebugLog.ContainsKey("Path") -eq $true) -and ([string]::IsNullOrEmpty($DebugLog.Path) -eq $false))
			{
				$LogPath = $DebugLog.Path
			}
			else
			{
                $LogPath = get_debug_path{}
			}

			$OutputMessage = ("[{0}] [{1}] {2} - [{3}({4})]" -f (Get-Date).tostring("yyyy-MM-dd HH:mm:ss:fff"), $PID, $DebugLog.Message, $DebugLog.FileName, $DebugLog.LineNumber)
			Write-Host $OutputMessage
			$Result_OutputMessage = Out-File -FilePath $LogPath -Append -Force -InputObject $OutputMessage
		}
		catch
		{
            Write-Host -ForegroundColor Red "[create_debug_log] Exception: $($_.Exception.GetType().FullName, $_.Exception.Message)"
			Switch -Regex ($_.exception) {
				"used by another process" {
					Write-Host "Oh no, Expection: $($_.exception)"
					Start-Sleep -s 1
					$Result_OutputMessage
				}
			}
        }		
	}
}