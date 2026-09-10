// IR-189 - Certutil Download
// Purpose: Identify certutil used to retrieve remote content.
// MITRE ATT&CK: T1105
#event_simpleName=ProcessRollup2
FileName="certutil.exe"
CommandLine=/(-urlcache|-split).*https?:\/\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)