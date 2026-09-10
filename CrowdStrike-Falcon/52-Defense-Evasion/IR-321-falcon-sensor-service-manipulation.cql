// IR-321 - Falcon Sensor Service Manipulation
// Purpose: Identify attempts to stop, delete, or reconfigure CrowdStrike Falcon services.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(CSFalconService|CrowdStrike|Falcon Sensor|falcon-sensor)/i
CommandLine=/(stop|delete|disable|uninstall|config)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)