// IR-217 - Impacket PsExec-Like Indicators
// Purpose: Hunt for common Impacket psexec/service execution artifacts.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
(CommandLine=/(impacket-psexec|psexec\.py)/i OR FileName=/^RemComSvc\.exe$/i OR ParentBaseFileName=/^services\.exe$/i FileName=/^[A-Za-z0-9]{4,12}\.exe$/)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)