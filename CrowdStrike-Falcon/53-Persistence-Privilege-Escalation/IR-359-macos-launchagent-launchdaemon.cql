// IR-359 - macOS LaunchAgent / LaunchDaemon Persistence
// MITRE ATT&CK: T1543.001
event_platform=Mac
#event_simpleName=ProcessRollup2
CommandLine=/(\/Library\/LaunchAgents\/|\/Library\/LaunchDaemons\/|~\/Library\/LaunchAgents\/|launchctl.*(bootstrap|load|enable|kickstart))/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)