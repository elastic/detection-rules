function ExecFromISO {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $ISOFile,
		[string] $procname,
		[string] $cmdline
	)
	$MountMeta = Mount-DiskImage -ImagePath $ISOFile -StorageType ISO -Access ReadOnly
	$DriveLetter = ($MountMeta | Get-Volume).DriveLetter
	if ($cmdline) {Start-Process -FilePath "$($DriveLetter):\$($procname)" -ArgumentList "$($cmdline)";}
	else {Start-Process -FilePath  "$($DriveLetter):\$($procname)" -WorkingDirectory "$($DriveLetter):\"} 
	Start-Sleep -s 2
	Stop-process -name $procname -Force -ErrorAction ignore
	Dismount-DiskImage -ImagePath $ISOFile | Out-Null
}
