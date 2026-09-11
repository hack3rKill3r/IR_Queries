// IR-444 - Web Shell-Like Files Written
// Purpose: Identify script files commonly used as web shells.
// MITRE ATT&CK: T1505.003
#event_simpleName=/FileWritten$/
TargetFileName=/\.(aspx|asp|ashx|php|jsp|jspx|cfm)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId],limit=20000)