// IR-281 - Linux Shell Execution
// Purpose: Identify common Linux shell execution.
// MITRE ATT&CK: T1059.004
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName=/^(bash|sh|zsh|dash|ksh)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)