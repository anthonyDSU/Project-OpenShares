$ExportPath = "NTFS-output.csv"
$SharePath = "all-shares-objects.txt"
$ErrorActionPreference='silentlycontinue'

Write-Output "Starting!"
$Total_Count = (Get-content -Path "$SharePath" | Measure-Object -Line).Lines
$Count=0

ForEach ($user in $(Get-Content $SharePath)) {
   $StartTime = $(get-date)
   $Count = $Count + 1
   Write-Output "$Count of $Total_Count :: Workign on $user"
   .\rg.exe --file .\regex.txt "$user" | Out-File -Append -FilePath $ExportPath
   $elapsedTime = $(get-date) - $StartTime
   $totalTime = "Duration:{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)

   Write-Output "   Finished on $user"
   Write-Output "   $totalTime"
   $OutputSize = Write-Output((Get-Item $ExportPath).Length/1KB)
   Write-Output "   Output File Size: $OutputSize`n`n "
}
