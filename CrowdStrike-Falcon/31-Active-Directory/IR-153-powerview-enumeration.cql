// IR-153 - PowerView Enumeration
// Purpose: Identify common PowerView reconnaissance functions.
#event_simpleName=ProcessRollup2
CommandLine=/(Get-DomainUser|Get-DomainComputer|Get-DomainGroup|Get-DomainTrust|Get-DomainController|Invoke-UserHunter)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)