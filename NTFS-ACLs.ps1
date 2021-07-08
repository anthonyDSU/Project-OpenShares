$block = {
    Param([string] $share_path)
    $ping = Test-Path $share_path

    if(($ping) -eq "True"){
        $Output = @()
        
        $Acl = Get-Acl -Path "$share_path"
        $Owner = $Acl.Owner
        $Group = $Acl.Group
        ForEach ($Access in $Acl.Access) {
            $Properties = [ordered]@{'Folder Name'=$share_path;'Group/User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited;'Inheritance Flags'=$Access.InheritanceFlags;'Propagation Flags'=$Access.PropagationFlags;'AccessControlType'=$Access.AccessControlType;'Owner'=$Owner;'GroupOFOwner'=$Group}
            $Output += New-Object -TypeName PSObject -Property $Properties 
        }
        $Output | Export-Csv -Path "NTFS-ACLS.csv" -Append
    }else{
	    write-output "Failed Connecting to: $share_path`n" 
    }
}
Get-Job | Remove-Job
$MaxThreads = 40
$shares = Import-Csv -Path "NTFS-output.csv"    

foreach($col in $shares){
    $share_path = $col.'Share_Path'
    While ($(Get-Job -state running).count -ge $MaxThreads){
        Start-Sleep -Milliseconds 3
    }
    Start-Job -Scriptblock $block -ArgumentList $share_path
}
While ($(Get-Job -State Running).count -gt 0){
    start-sleep 1
}
foreach($job in Get-Job){
    $info= Receive-Job -Id ($job.Id)
}
Get-Job | Remove-Job
