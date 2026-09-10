// IR-170 - Service Modification with SC
// Purpose: Identify service create/config/start/stop/delete operations.
// MITRE ATT&CK: T1543.003 / T1562.001
#event_simpleName=ProcessRollup2
FileName="sc.exe"
CommandLine=/(create|config|start|stop|delete)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)