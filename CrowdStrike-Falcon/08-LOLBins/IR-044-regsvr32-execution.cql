// IR-044 - Regsvr32 Execution
// Purpose: Review regsvr32 execution for suspicious DLL registration or proxy execution.
// MITRE ATT&CK: T1218.010
#event_simpleName=ProcessRollup2
FileName="regsvr32.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)