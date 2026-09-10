// IR-292 - macOS launchctl Persistence
// Purpose: Identify launchctl commands used to load/start persistence.
// MITRE ATT&CK: T1543.001
event_platform=Mac
#event_simpleName=ProcessRollup2
FileName="launchctl"
CommandLine=/(load|bootstrap|enable|kickstart)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)