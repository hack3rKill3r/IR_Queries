// IR-023 - WMIC Execution
// Purpose: Identify WMIC use for discovery or remote execution.
// MITRE ATT&CK: T1047
#event_simpleName=ProcessRollup2
FileName="wmic.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)