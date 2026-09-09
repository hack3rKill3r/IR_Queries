// IR-042 - MSHTA Execution
// Purpose: Identify HTML Application Host execution, frequently abused for proxy execution.
// MITRE ATT&CK: T1218.005
#event_simpleName=ProcessRollup2
FileName="mshta.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)