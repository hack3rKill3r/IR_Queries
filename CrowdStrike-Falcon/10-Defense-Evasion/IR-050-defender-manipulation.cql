// IR-050 - Microsoft Defender Manipulation
// Purpose: Identify command-line attempts to weaken Defender or add exclusions.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)