// IR-164 - LaZagne Execution
// Purpose: Identify LaZagne by filename or command-line reference.
// MITRE ATT&CK: T1555
#event_simpleName=ProcessRollup2
(FileName=/lazagne/i OR CommandLine=/lazagne/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)