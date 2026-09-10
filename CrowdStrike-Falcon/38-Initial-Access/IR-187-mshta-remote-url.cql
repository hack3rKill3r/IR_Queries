// IR-187 - MSHTA with Remote URL
// Purpose: Identify mshta loading remote HTTP/HTTPS content.
// MITRE ATT&CK: T1218.005 / T1105
#event_simpleName=ProcessRollup2
FileName="mshta.exe"
CommandLine=/https?:\/\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)