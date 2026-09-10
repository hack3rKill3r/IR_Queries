// IR-293 - macOS LaunchAgent/LaunchDaemon plist References
// Purpose: Hunt for process command lines referencing common persistence directories.
// MITRE ATT&CK: T1543.001
event_platform=Mac
#event_simpleName=ProcessRollup2
CommandLine=/(\/Library\/LaunchAgents\/|\/Library\/LaunchDaemons\/|~\/Library\/LaunchAgents\/)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)