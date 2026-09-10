// IR-214 - Remote Service Creation Commands
// Purpose: Identify sc.exe commands targeting remote systems using \\HOST syntax.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
FileName="sc.exe"
CommandLine=/\\\\[^\\\s]+\s+(create|config|start)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)