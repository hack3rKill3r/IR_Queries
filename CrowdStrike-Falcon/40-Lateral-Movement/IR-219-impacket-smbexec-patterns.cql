// IR-219 - Impacket SMBExec-Like Indicators
// Purpose: Hunt for service-based remote execution patterns associated with smbexec.py.
// MITRE ATT&CK: T1021.002 / T1569.002
#event_simpleName=ProcessRollup2
(CommandLine=/(impacket-smbexec|smbexec\.py)/i OR (ParentBaseFileName="services.exe" AND FileName="cmd.exe"))
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)