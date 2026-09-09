// IR-049 - Windows Event Log Clearing
// Purpose: Identify common command-line methods used to clear Windows event logs.
// MITRE ATT&CK: T1070.001
#event_simpleName=ProcessRollup2
((FileName="wevtutil.exe" AND CommandLine=/\bcl\b/i) OR CommandLine=/Clear-EventLog/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)