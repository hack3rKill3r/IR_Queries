// IR-415 - PsExec Ransomware Deployment Pattern
// Purpose: Identify PsExec remote execution with payload-like command lines.
// MITRE ATT&CK: T1569.002 / T1486
#event_simpleName=ProcessRollup2
FileName=/^(psexec|psexec64)\.exe$/i
CommandLine=/(\\\\|\.exe|\.bat|\.cmd|\.ps1)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData],limit=20000)