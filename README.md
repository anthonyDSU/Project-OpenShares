# Project-OpenShares

## Chapter 1: Introduction to Shares & Permissions!

Towards writing the end of this series, I decided to switch from posting a picture tutorial and focus more on GIFs. I found GIFs to deliver more knowledge in a compact amount of time.

Created a demo AD lab for this series. Here are the lab details:

The machine we see in the GIF is called '**Server1**', with the user 'me-forest\\**granger**' (Green Ranger). We have another server called '**Server2**' with the user 'me-forest\\**branger**' (Blue Ranger). In this scenario, branger on Server2 is the adversary on the hunt looking for the low-hanging fruits. (I missed my opportunity of making red ranger!)

On Server 1, I created a folder called Share1, with some subfolders and files inside. Share1 is then shared with the '**Everybody**' group.





# Chapter 2: Gathering all File Shares

There are quite a few different ways to collect all file shares within an enterprise. I will go over the internal red team, outside red team, and blue teams viewpoint.

Through the Infosec community, there are several available scripts can get the job done.

**Red Teams Perspective:**

- [Invoke-ShareFinder.ps1](https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1) 
- [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/) - From the PowerSploit Repsoitory
- Powershell/CMD cmdlets, no scripts needed. (more info below)
- CrackMapExec

**Blue Team & Internal Red Team Perspective:**

- Tenable Nessus & Security Center
  - 10395 | Microsoft Windows SMB Shares Enumeration
  - 10396 | Microsoft Windows SMB Shares Access
  - 23974 | Microsoft Windows SMB Share Hosting Office Files
  - 24271 | SMB Shares File Enumeration (via WMI)
  - 60119 | Microsoft Windows SMB Share Permissions Enumeration
- and the multiple software's available out there..

**Gathering File Shares**

I will assume,  like most enterprises, tenable logs are ingested into Splunk. We can use plugin [60119](https://www.tenable.com/plugins/nessus/60119) from the list above to pull down all Windows SMB Share Permissions. Typically under the event tab, the information will be posted like below. We are going to focus on the pluginText (also known as 'output' in the new tenable.io) parameters towards the bottom of the picture.

The pluginText field contains information useful for determining the who|what|where permissions of the share. In the example above, we can see that shared path: **\\\127.0.0.1\print$** allows two groups: 

* Everyone
  * Permissions: Read, Execute

* Builtin\Administrators
  * Permissions: Read, Write, Execute

This example is on the more accessible side. There are machines with numerous shares, all with different levels|groups of permissions. With that said, I have created the Splunk Query below that will make the data more readable at a higher level and easier to export for the next section.

**Splunk Query**

Get a list of all shares from Splunk:

```bash
index=tenable sourcetype="tenable*" pluginID=60119 daysago=120 | table dnsName, pluginID, pluginName, pluginText, ip | eval pluginText=split(pluginText,"Share path") | mvexpand pluginText 
| where like(pluginText," : %") | eval Permissions=split(pluginText,"[*]")
| mvexpand Permissions
| where like(Permissions," Allow%")
| rex field=Permissions "Allow\sACE\sfor\s(?<Permission_For>.*):"
| rex field=pluginText "^\s:\s(?<Share_Path>.*)"
| rex field=pluginText "Local\spath\s:\s(?<Local_Path>.*)"
| rex field=pluginText "Comment\s:\s(?<Description>.*)"
| eval repShare_Path = replace(Share_Path, "\\\\","@")
| rex field=repShare_Path "@@(?<Host_in_Share>.*?)@(?<Share>[^@]+$)"
| eval Permission =if(match(Permissions,"(?i)0x001f01ff|0x001301bf|0x001201bf|0x001301ff"),"RWX",Permission)
| eval Permission =if(match(Permissions,"(?i)0x001200a9|0x001e00e9|0x00120089"),"RX",Permission)
| eval Share_Path=replace(Share_Path, "127.0.0.1", dnsName)
| eval Share_Path = replace(Share_Path, ".domain.com","")
| table ip, dnsName, Host_in_Share, Share, Permission_For, Permission, Share_Path, Local_Path, Description
| where Share != "print$" | where Share != "IPC$"
| dedup Share_Path
```

There is quite a lot to take in here, so I will give an example of how Splunk looks after running the query:

From the image above, we can see many field separations. The query will first look at the pluginText field and split if there is more than one listed share. It will then parse out the Permissions_For, Share_Path, Local_Path, Description fields out of it. Splunk gets weird with backslashes, so I replaced all backslashes with the @ sign on the Share_Path field to alleviate that potential issue.

Towards the middle of the query is where we get into the permissions. Those sequences of hex characters (example: 0x001f01ff) can be converted to Security Descriptor Definition Language (SDDL). For more context on this, the link below from Microsoft will show you the conversion:

> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070

Moving on towards the bottom of the query will replace all home addresses (127.0.0.1) with the dnsName it pulled. In other words, were turning **\\\127.0.0.1\print$** into **\\\dnsName.domain.com\print$**. The following line then removes the domain from the share_path, going from **\\\dnsName.domain.com\print$** to **\\\dnsName\print$**. This is very useful to get rid of duplicate shares within the enterprise.

Finally, we are going to make the table with the **table** syntax, followed by not printing any shares that contain **print$** & **IPC$**.

You will be left with an immaculate table with all the necessary fields. From here, you can export this to a CSV file that will be used in another section.





# Chapter 3: Gathering all NTFS Permissions

In Chapter 2, we gathered all the Share permissions. This Chapter is focused on NTFS. For more information on the difference, please read Chapter 1.

As you know by now, NTFS permissions can get interesting. 

I created the PowerShell Script below to pull all the ACLs for the shares we found in the previous Chapter. I will go through some of the code in case you'll need to change it to fit your needs. To give you some time frame, across a list of ~3,000 shares, it took around 8 minutes with 40 threads to complete.

The following script takes two parameters, Input, and Output. The input would be the output from Chapter 2. The output for this script is named NTFS-ACLS.csv.

```Powershell
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
```

Above is the threaded PowerShell script that will pull all the ACLs + information of a given share. By default, it's set to 40 threads, as that is what worked on the machine I was given during my assessment. You'll need to change the **$shares** variable path to where you have your .CSV stored. In short, the script first opens the .CSV file that we are supplying and looking for the column that is named '**Share_Path**'. From there, it will make a thread of each line item in the csv (row). We're utilizing the Get-ACL cmdlet:

> The `Get-Acl` cmdlet gets objects that represent the security descriptor of a file or resource. The security descriptor contains the access control lists (ACLs) of the resource. The ACL specifies the permissions that users and user groups have to access the resource.
>
> https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7

It will then loop through all of the users|groups that have access, and print all information to another csv file, in this case: **NTFS-ACLS.csv**

The above image is how the output CSV will look from my Powershell script.

Lets break down each column:

1. Folder Name: This would be the share name.

2. Group/User: This would be the group or user.

3. Permissions: This would be the permissions for the group or user. In the example above, the **Everyone** group has the permissions for ReadAndExecute, Synchronize. 

   > **ReadAndExecute:** Specifies the right to open and copy folders or files as read-only, and to run application files. This right includes the [Read](https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=dotnet-plat-ext-3.1#System_Security_AccessControl_FileSystemRights_Read) right and the [ExecuteFile](https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=dotnet-plat-ext-3.1#System_Security_AccessControl_FileSystemRights_ExecuteFile) right.
   >
   > 
   >
   > **Synchronize:** Specifies whether the application can wait for a file handle to synchronize with the completion of an I/O operation. This value is automatically set when allowing access and automatically excluded when denying access.

   

   While the group **NT AUTHORITY\SYSTEM** has FullControl permissions.

   > **FullControl:** Specifies the right to exert full control over a folder or file, and to modify access control and audit rules. This value represents the right to do anything with a file and is the combination of all rights in this enumeration.

   		For more information on flag attributes, visit this Microsoft page:

   > 				https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights

4. Inherited: The purpose of using ACL inheritance is so that a newly created file or directory can inherit the ACLs they are intended to inherit.

5. Inheritance Flags:  Inheritance flags specify the semantics of inheritance for access control entries (ACEs). In our example we see both `ContainerInheritance` and the `ObjectInheritance` flags set. This indicates that the permission to be propagated to all child directories *and* files.

   | Inheritance Flag | Meaning                                                      |
   | :--------------- | :----------------------------------------------------------- |
   | ContainerInherit | Propagate to child containers (directories).                 |
   | None             | Do not propagate this permission to any child containers or objects. |
   | ObjectInherit    | Propagate to child objects (files).                          |

6. Propagation Flag: The default Windows behavior is `None`. See the table below for more detail on the three Propagation Flag options. Setting this flag to `InheritOnly` will cause the access rule to *only* apply to child objects of the container.

   | Propagation Flag   | Meaning                                                      |
   | :----------------- | :----------------------------------------------------------- |
   | InheritOnly        | Specifies that the ACE is propagated only to child objects. This includes both container and leaf child objects. |
   | None               | Specifies that no inheritance flags are set.                 |
   | NoPropagateInherit | Specifies that the ACE is not propagated to child objects.   |

7. Access Control: There are only two access control types. `Allow` and `Deny`. Allow means we are allowing the permission, e.g., we are allowing a user to write to this directly. 

   Deny will specifically deny a right, and takes precedence over Allow permissions. So, if a user has a Modify/Allow entry and also a Read/Deny that user will have all Modify rights *except* read.

8. Owner: This is the owner of the share.

9. Group: This is the group of the owner of the share.

### Extra, Extra, Share Size

During my assessment, I wanted to pull the size of each file share. I used the command below. You can add this command to the script above to have it auto-populate the output CSV file. Share size is not super essential and does not yield better output. I used the size of the network share to gauge the lower hanging fruit during my assessment.

```powershell
$share_path = "\\example\share"
$Share_Size = "{0} MB" -f ((Get-ChildItem '$share_path' -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
```

**Update:** I found that the following Get-ChildItem function does take quite a long time, depending on folder size. I will be updating this section once I start to compile all the scripts together to make one application. With that said, I have done testing with various inbuilt windows executables and found that robocopy is pretty dang quick! 

```powershell
robocopy /l /nfl /ndl \\server\folder$ c:\temp /e /bytes
```

More details can be found at Microsoft Docs: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy



# Chapter 4: Looking for Credentials + More

In Chapter 3, we gathered all the Share NTFS permissions at the first folder level. This chapter focuses on getting user credentials, PII, and all sorts of fun red team information.

Let us recap on the progress from the previous Chapters:

Chapter 2 used which method was preferred and dump a list of all shares within the domain. We then took that list and ran my NTFS ACL PowerShell script against those to dump all ACLs. I should note that not every share dumped from Chapter 2 means we have access to it. Chapter 3 determines if we can connect successfully to the share, aka if we can dump ACLs -- we connected to it.

Looking at it from the red teams perspective, as a regular domain user doing an assessment, I am looking at a few important groups that I automatically below to:

* **NT AUTHORITY\Authenticated Users**
* **Domains Users**
* **EVERYONE**
* **Builtin\Users**

With that said, you can filter out only the groups above if you are interested in seeing a different level of permissions you may have.

Moving on, we can remove all duplicates from the CSV at this point. We already have access and want to get an idea + separate CSV going of all shares. You can easily do this in excel using the remove duplicate function on the share name column. At this moment, we should have a single text file with a bunch of shares each on a line.

### TLDR - Chapter 4

We will utilize an open-source project called RIPGREP to search recursively through each share, parsing out for regexes I made. The idea is that we do not know if a password is within a file unless it strictly tells us. For instance, **!@#qwe123** within a file does not tell us much and would be hard to search for if we are looking for anything of that sort, but if a file contains: **pass: "!@#qwe123"**, the pass variable makes it known what were looking at. 

In short, we will be looking at credentials, usernames, password parameters and gathering all of that information. We are also going to grab all SSH private keys, bitcoin addresses, SSNs, and any other PII we might run into. For each piece of object that is found, it will be written to a file. Each object (aka signature) will have its separate line.

We will be searching through all files, even compressed files (except .zip). It includes binary, executables, documents, pdf, you name it, it will be searched. Doesn't it have a file extension? No worries, it will also be searched. All hidden directories and files will be searched.

### RIPGREP

I utilize RIPGREP to do all the hunting. Think of grep..on steroids! I went down the rabbit hold of testing all greplike tools (ack, the silver searcher, gnugrep, ag, ucg, pt, sift, ect), best results came from rg.

> https://github.com/BurntSushi/ripgrep
>
> ripgrep is a line-oriented search tool that recursively searches your current directory for a regex pattern. By default, ripgrep will respect your .gitignore and automatically skip hidden files/directories and binary files. ripgrep has first class support on Windows, macOS and Linux, with binary downloads available for [every release](https://github.com/BurntSushi/ripgrep/releases). ripgrep is similar to other popular search tools like The Silver Searcher, ack and grep.

We'll need to first download RIPGREP, for my example I'll be downloading it to c:\

You'll need to create a file within the RIPGREP directory called rg.rc, and set your path variable accordingly.

On windows search for 'env', within the System Properties window that opened, click on 'Environment Variables...', under the first section 'User Variables', add the following:

* **Variable Name:** RIPGREP_CONFIG_PATH
* **Value:** C:\rg\rg.rc

You'll may need to restart at this point. If having issues, please refer to the RG wiki links.

**Below I break down each file and it's purpose, these will be outdated and you should refer back to my github page for the latest code update.**

### Capture-Objects.ps1

This powershell script is going to be the main hub connecting everything together.  The following script takes two parameters, Input and Output. The input is from the output of the previous script: NTFS-ACLS.csv, and the output is all-shares-objects.txt.

```powershell
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
```

---------

### Rg.rc

This rc file allows for setting RIPGREP parameters within a single file, please visit their GitHub page to get an understanding of each parameter.

```bash
--ignore-case
--hidden
--max-columns-preview
--max-columns=300
--max-filesize=25M
--stats
--ignore-messages
--color=never
--search-zip
--max-count=15
--pcre2
```

----------

### Regex.txt & More-regex.txt

Both of these files contained some great regexes for you to use on your hunt.

 

# Chapter 5: Got a list of objects, now what?

Hopefully, at  this point, you will have an output large enough to have an analyst do a deep dive on!

Here are some tricks I learn along the way:

- If working with excel, remove duplicates on all fields. This will cut down the size of your file.
- If running into credentials on a particular share, go check out the files creation date :)
- If running into PII or sensitive documents, it will be situational, but I recommend less eyes on that. Make a note and move on to the next.
- If finding bitcoin address within a file, you might just get yourself access to a web-server :)  (The bitcoin address are usual JavaScript code that is compiled with libraries already, nice lead way though)

For myself, I created a Splunk dashboard to ingest the information that was obtained. I can now give better accurate risk analysis based on which shares contain information and their permissions levels. 

I will be posting the Splunk dashboard code within my GitHub.



# Mitigation:

- Groups everywhere. Do not assign permissions to individuals. Even if you have to create 200 groups, so be it. It is far easier to manage 200 groups than 2000 one-off permissions. When creating groups, follow a uniform naming convention and fill in the description field in AD.
- Do not have users store plain-text credentials within documents. This can be avoided with training sessions and routine network scanning that looks for such credentials. Training sessions and more training sessions.
- Avoid breaking permission inheritance as much as possible. There will be a few folders where this may be necessary, but generally, try and avoid it.
- Avoid giving users "full control." Full control means changing permissions, which in most businesses, users should not need to do (all permission changes should be logged, anyway). Modify permissions should be all that's necessary for users.
- Always have SYSTEM-Full and Administrators-Full present in every ACL. It should be set at the root of your data volume and inherited everywhere else. If you break inheritance, make sure these permissions are there. It will make it much easier to manage the server.



# Future Research

Some future research includes cleaning up the code to make the project more friendly for the community. I have a list of add-ons that I am currently working to implement soon. Furthermore, I will like to continue to test out more grep-like tools and keep-up with the latest and greatest.



# References

- ​	[NTFS  Permissions vs Share: Everything You Need to Know](https://www.varonis.com/blog/ntfs-permissions-vs-share/)
- ​	[Unsecured  Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)  
- ​	[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)

