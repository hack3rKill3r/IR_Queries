// IR-323 - Disable Defender Real-Time Monitoring
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/Set-MpPreference.*DisableRealtimeMonitoring.*(true|1)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)