// IR-201 - PsExec Source Execution
// Purpose: Identify PsExec launched from a source endpoint for remote execution.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
FileName=/^(psexec|psexec64)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData,TargetProcessId], limit=20000)