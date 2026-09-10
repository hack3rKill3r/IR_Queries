// IR-154 - ActiveDirectory PowerShell Module Enumeration
// Purpose: Identify common AD PowerShell cmdlets used during enumeration.
#event_simpleName=ProcessRollup2
CommandLine=/(Get-ADUser|Get-ADComputer|Get-ADGroup|Get-ADDomain|Get-ADForest|Get-ADDomainController)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)