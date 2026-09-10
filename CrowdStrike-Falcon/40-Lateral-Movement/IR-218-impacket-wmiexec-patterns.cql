// IR-218 - Impacket WMIExec-Like Indicators
// Purpose: Hunt for command-line or process patterns associated with wmiexec.py.
// MITRE ATT&CK: T1047
#event_simpleName=ProcessRollup2
(CommandLine=/(impacket-wmiexec|wmiexec\.py)/i OR (ParentBaseFileName="wmiprvse.exe" AND FileName="cmd.exe"))
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)