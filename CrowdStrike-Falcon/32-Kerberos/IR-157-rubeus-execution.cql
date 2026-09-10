// IR-157 - Rubeus Execution
// Purpose: Identify Rubeus by filename or command-line reference.
// MITRE ATT&CK: T1558
#event_simpleName=ProcessRollup2
(FileName=/rubeus/i OR CommandLine=/rubeus/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)