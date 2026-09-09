// IR-043 - Rundll32 Execution
// Purpose: Review rundll32 execution and command lines for suspicious DLL proxy execution.
// MITRE ATT&CK: T1218.011
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)