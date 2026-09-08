// IR-021 - PsExec Execution
// Purpose: Identify Sysinternals PsExec execution.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
FileName=/^(psexec|psexec64)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)