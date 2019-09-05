#Author - James Jenkinson (ES2)
#=========================================================================Known Issues==================================================================================================================================================================================================================#
#Error Action Ignore is not supported on 2008R2 (Safely Ignore)
#Zipping Fails unless using Powershell Version 5
#Get-ADForest and Get-ADDomain Fail on Windows Server 2008R2
#=========================================================================Version History===============================================================================================================================================================================================================#
#V1.0 - Script created
#V1.1 - Added administrator run as
#V1.2 - Added dcdiag DNS test for isolated DNS results away from verbose results
#V1.3 - Added variables and edited folder names, added folder creation
#V1.4 - Added write-host outputs
#V1.5 - Added netdom query for output of FSMO role holders
#V1.6 - Added Get-ADTrust cmdlet for extra output
#V1.7 - Added new folder creations to categorise the data, 
#V1.8 - Added commands to export Domain Admins, Enterprise Admins and Schema Admins separately
#V1.9 - Added commands to export a list of Users who have not logged in for 90 days and another one for all enabled users with no password expiry
#V1.10 - Added in HTML report for GPO for easier reading, added commands to get Forest and Domain function levels
#V2.0 - Added in recursive delete at the start of the script to ensure folders dont exist, Added Zip function into script, Added recursive delete at the end to remove all unzipped content,
#       replaced all outputs with PowerShell native out-file and removed error actions on deletes of folders
#V2.1 - Added comand to export unlinked GPO into a txt file and Active Direcotry Backup status
#V2.2 - Added in Check for AD Recycle Bin status and Default Password Policy information
#V2.3 - Replaced Command to get Domain Controller list with Powershell native command and added extra information gathering
#V2.4 - Added command to get formatted list of Trust information, cleaned up and formatted code
#V2.5 - Added in a check for zip file before deleting contents incase the zipping fails
#V2.6 - Added in ignore for get-adtrust command, Added in command to extract GPO with no settings
#=========================================================================Script Preparation=============================================================================================================================================================================================================#

#Script designed to pull as much information from the target domain as possible to provide a clear picture of its current health state.
    write-host Health Check Starting

#Launch Powershell as Administrator
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Set Variables
    $D = $env:USERDOMAIN
    $H = HOSTNAME

#Ensure Directories don't already exist
    Remove-Item -Path c:\temp\adhealth -recurse -ErrorAction Ignore
    Remove-Item -Path c:\temp\"$D"_adhealth.zip -ErrorAction Ignore

#Create the Folder to store Results
    md -Path "C:\Temp\ADHealth"
    md -Path "C:\Temp\ADHealth\SecurityGroups"
    md -Path "C:\Temp\ADHealth\DCHealth"
    md -Path "C:\Temp\ADHealth\GroupPolicy"
    md -Path "C:\Temp\ADHealth\UserAccounts"

#=========================================================================Script Body=====================================================================================================================================================================================================================#

#Get a list of all known Domain Controllers the Domain is aware of, for manual review and match to known controllers
    write-host Obtaining list of Domain Controllers
    Get-ADDomainController -Filter * | Select-Object Name,OperatingSystem,IsGlobalCatalog,Site | Out-File C:\temp\ADHealth\DCHealth\"$D"_DCList.txt

#Get the Forest and Domain Function levels
    write-host Checking Domain and Forest Function levels
    (Get-ADForest).ForestMode | Out-File c:\temp\ADHealth\DCHealth\"$D"_ForestMode.txt
    (Get-ADDomain).DomainMode | Out-File c:\temp\ADHealth\DCHealth\"$D"_DomainMode.txt

#Check the overall health of the Domain FSMO Roles
    write-host Checking health of FSMO Roles...this can take some time
    netdom query fsmo | Out-file c:\temp\ADHealth\DCHealth\"$D"_FSMORoleHolders.txt
    dcdiag /f:c:\temp\ADHealth\DCHealth\"$H"_dcdiag.txt
    dcdiag /test:dns /f:c:\temp\ADHealth\DCHealth\"$H"_dcdiagDNS.txt
    dcdiag /v /c /f:c:\temp\ADHealth\DCHealth\"$H"_dcdiagverb.txt

#Check the status of the AD Recycle Bin
    Write-Host Checking AD Recycle Bin status
    $ADRecBin = (Get-ADOptionalFeature -Filter "Name -like 'Recycle Bin Feature'").EnabledScopes
    if ($ADRecBin.Count -gt 0){"AD Recycle Bin is enabled"| Out-file c:\temp\ADHealth\DCHealth\"$H"_RecBinStat.txt} 
    else {"AD Recycle Bin is not enabled"| Out-file c:\temp\ADHealth\DCHealth\"$H"_RecBinStat.txt}

#Check the replication status between all active Domain Controllers
    write-host Checking replication health
    repadmin /replsummary | Out-file c:\temp\ADHealth\DCHealth\"$H"_replsum.txt
    repadmin /showrepl * /verbose /all /intersite | Out-file c:\temp\ADHealth\DCHealth\"$H"_replverb.txt
    repadmin /showbackup | Out-File c:\temp\ADHealth\DCHealth\"$H"_replbackup.txt

#Get a list of active trusts
    write-host Getting list of trusts
    Repadmin /showtrust * | Out-file c:\temp\ADHealth\DCHealth\"$D"_repltrust.txt
    Get-ADTrust -Filter * -ErrorAction Ignore | Out-file c:\temp\ADHealth\DCHealth\"$D"_ADtrust.txt
    Get-ADTrust -Filter * -ErrorAction Ignore | Select-Object Name,Direction,ForestTransitive,SelectiveAuthentication | Out-file c:\temp\ADHealth\DCHealth\"$D"_ADtrustFormat.txt

#Get a list of Certificate Authorities according to the Domain
    write-host Getting list of Certificate Authorities
    certutil -dump | Out-file c:\temp\ADHealth\DCHealth\"$D"_CertAuth.txt

#Create a report from Group Policy detailing all information for peer review
    write-host Creating GPO Report
    Get-GPOReport -All -ReportType xml -Path C:\temp\ADHealth\GroupPolicy\"$D"_GPOReport.xml
    Get-GPOReport -All -ReportType html -Path C:\temp\ADHealth\GroupPolicy\"$D"_GPOReport.html

#Get the Password Policies in Domain
    Get-ADDefaultDomainPasswordPolicy | Out-File C:\temp\ADHealth\GroupPolicy\"$D"_DefPassPol.txt
    Get-ADFineGrainedPasswordPolicy -Filter * | Out-File C:\temp\ADHealth\GroupPolicy\"$D"_FinGrPassPol.txt

#Create a report from Group Policy listing all Linkless Objects
    function IsNotLinked($xmldata){
    If ($xmldata.GPO.LinksTo -eq $null) {
        Return $true
    }
    
    Return $false
}

    $unlinkedGPOs = @()

    Get-GPO -All | ForEach { $gpo = $_ ; $_ | Get-GPOReport -ReportType xml | ForEach { If(IsNotLinked([xml]$_)){$unlinkedGPOs += $gpo} }}

    If ($unlinkedGPOs.Count -eq 0) {
    "No Unlinked GPO's Found"
}
    Else{
    $unlinkedGPOs | Select DisplayName | Out-File C:\temp\ADHealth\GroupPolicy\"$D"_UnlinkedGPO.txt
}

#Create a report from Group Policy listing all Objects with no Settings
    function HasNoSettings{
    $cExtNodes = $xmldata.DocumentElement.SelectNodes($cQueryString, $XmlNameSpaceMgr)
  
    foreach ($cExtNode in $cExtNodes){
        If ($cExtNode.HasChildNodes){
            Return $false
        }
    }
    
    $uExtNodes = $xmldata.DocumentElement.SelectNodes($uQueryString, $XmlNameSpaceMgr)
    
    foreach ($uExtNode in $uExtNodes){
       If ($uExtNode.HasChildNodes){
            Return $false
        }
    }
    
    Return $true
}

    function configNamespace{
    $script:xmlNameSpaceMgr = New-Object System.Xml.XmlNamespaceManager($xmldata.NameTable)

    $xmlNameSpaceMgr.AddNamespace("", $xmlnsGpSettings)
    $xmlNameSpaceMgr.AddNamespace("gp", $xmlnsGpSettings)
    $xmlNameSpaceMgr.AddNamespace("xsi", $xmlnsSchemaInstance)
    $xmlNameSpaceMgr.AddNamespace("xsd", $xmlnsSchema)
}

    $noSettingsGPOs = @()

    $xmlnsGpSettings = "http://www.microsoft.com/GroupPolicy/Settings"
    $xmlnsSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"
    $xmlnsSchema = "http://www.w3.org/2001/XMLSchema"

    $cQueryString = "gp:Computer/gp:ExtensionData/gp:Extension"
    $uQueryString = "gp:User/gp:ExtensionData/gp:Extension"

    Get-GPO -All | ForEach { $gpo = $_ ; $_ | Get-GPOReport -ReportType xml | ForEach { $xmldata = [xml]$_ ; configNamespace ; If(HasNoSettings){$noSettingsGPOs += $gpo} }}

    If ($noSettingsGPOs.Count -eq 0) {
        "No GPO's Without Settings Were Found"
}
    Else{
        $noSettingsGPOs | Select DisplayName,Owner,GPOStatus | Out-File C:\temp\ADHealth\GroupPolicy\"$D"_NoSettingsGPO.txt
}

#Grab all AD User accounts within the Domain
    write-host Creating AD User Report
    get-aduser -filter * -properties * | export-csv c:\temp\ADHealth\UserAccounts\"$D"_ADUserReport.csv -NoTypeInformation

#Grab all AD User accounts within Domain that have not been logged into for over 90 Days and are enabled
    $90Days = (get-date).adddays(-90)
    Get-ADUser -properties * -filter {(lastlogondate -notlike "*" -OR lastlogondate -le $90days) -AND (passwordlastset -le $90days) -AND (enabled -eq $True) -and (whencreated -le $90days)} | select-object name, SAMaccountname, passwordExpired, PasswordNeverExpires, logoncount, whenCreated, lastlogondate, PasswordLastSet, lastlogontimestamp | export-csv c:\Temp\ADHealth\UserAccounts\"$D"_90DLastLogon.csv

#Grab all AD User accounts within Domain that are enabled with No Password Expiry
    Get-ADUser -properties * -filter {(enabled -eq $True) -and (PasswordNeverExpires -eq $True)} | select-object name, SAMaccountname, PasswordNeverExpires, logoncount, whenCreated, lastlogondate, PasswordLastSet, lastlogontimestamp | export-csv c:\Temp\ADHealth\UserAccounts\"$D"_EnabledNonExpire.csv

#Grab all AD Security Groups within the Domain and their Memberships
    write-host Creating AD Group Report...this can take some time
    $Groups = Get-ADGroup -Filter{GroupCategory -eq "security"}
    $Table = @()
    $Record = @{
        "Group Name" = ""
        "Name" = ""
        "Username" = ""
}
    Foreach ($Group in $Groups) {
    $Arrayofmembers = Get-ADGroupMember -Identity $Group.Name -Recursive | select name,samaccountname
        foreach ($Member in $Arrayofmembers) {
            $Record."Group Name" = $Group
            $Record."Name" = $Member.name
            $Record."UserName" = $Member.samaccountname
            $objRecord = New-Object PSObject -property $Record
            $Table += $objrecord
  }
}
    $Table | export-csv C:\temp\ADHealth\SecurityGroups\"$D"_SecGrpReport.csv -NoTypeInformation

#Grab all Domain Admins within the domain
    Get-ADGroupMember "Domain Admins" | select-object name,samaccountname,objectClass | export-csv C:\temp\ADHealth\SecurityGroups\"$D"_DomAdminRpt.csv -NoTypeInformation
    
#Grab all Enterprise Admins within the domain
    Get-ADGroupMember "Enterprise Admins" | select-object name,samaccountname,objectClass | export-csv C:\temp\ADHealth\SecurityGroups\"$D"_EntAdminRpt.csv -NoTypeInformation

#Grab all Schema Admins within the domain
    Get-ADGroupMember "Schema Admins" | select-object name,samaccountname,objectClass | export-csv C:\temp\ADHealth\SecurityGroups\"$D"_SchAdminRpt.csv -NoTypeInformation

#Grab all Administrators within the domain
    Get-ADGroupMember "Administrators" | select-object name,samaccountname,objectClass | export-csv C:\temp\ADHealth\SecurityGroups\"$D"_AdminRpt.csv -NoTypeInformation

#=========================================================================Prepare the Results=============================================================================================================================================================================================================#

#Copy all content to zip file
    write-host Zipping contents
    Compress-Archive -Path C:\temp\ADHealth -CompressionLevel Optimal -DestinationPath C:\temp\"$D"_adhealth

#Delete unzipped content
    $FileName = "C:\temp\*_adhealth.zip"
    if (Test-Path $FileName) 
{
    Remove-Item -Path c:\temp\adhealth -recurse
    write-host Script has finished running, please go to C:\Temp\ and send the ADHealth zip file to ES2
}
    else { write-host Script has finished running, but zipping failed, please go to C:\Temp\, zip the ADHealth folder and send to ES2 }

    
    read-host Press ENTER to close