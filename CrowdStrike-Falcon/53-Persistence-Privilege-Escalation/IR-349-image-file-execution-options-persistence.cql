// IR-349 - IFEO Debugger Persistence
// Purpose: Identify Image File Execution Options debugger modifications.
// MITRE ATT&CK: T1546.012
#event_simpleName=ProcessRollup2
CommandLine=/(Image File Execution Options|IFEO).*(Debugger|GlobalFlag)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)