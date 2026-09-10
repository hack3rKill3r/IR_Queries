// IR-206 - WMIC Remote Node Execution
// Purpose: Identify WMIC commands targeting remote systems.
// MITRE ATT&CK: T1047
#event_simpleName=ProcessRollup2
FileName="wmic.exe"
CommandLine=/\/node:/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)