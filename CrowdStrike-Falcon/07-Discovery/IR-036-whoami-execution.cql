// IR-036 - WHOAMI Execution
// Purpose: Identify account and privilege discovery using whoami.
// MITRE ATT&CK: T1033
#event_simpleName=ProcessRollup2
FileName="whoami.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)