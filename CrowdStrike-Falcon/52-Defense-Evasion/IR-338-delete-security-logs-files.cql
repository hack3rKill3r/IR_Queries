// IR-338 - Security Log File Deletion References
// Purpose: Hunt for commands deleting EVTX or common security log files.
// MITRE ATT&CK: T1070.001
#event_simpleName=ProcessRollup2
CommandLine=/(del|erase|remove-item|rm).*(\.evtx|Windows\\System32\\winevt\\Logs|security\.log|auth\.log)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)