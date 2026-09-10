// IR-165 - Browser Credential Store References
// Purpose: Identify process command lines referencing common browser credential databases.
#event_simpleName=ProcessRollup2
CommandLine=/(Login Data|Web Data|Cookies|Local State)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)