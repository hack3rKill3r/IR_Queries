// IR-249 - Cobalt Strike String Indicators
// Purpose: Hunt for command-line references commonly associated with Cobalt Strike.
// MITRE ATT&CK: T1071 / T1059
#event_simpleName=ProcessRollup2
CommandLine=/(cobaltstrike|beacon\.dll|artifactkit|sleepmask|execute-assembly)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)