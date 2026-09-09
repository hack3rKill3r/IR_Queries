// IR-061 - Remote Management Tools
// Purpose: Identify commonly abused legitimate remote access software.
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/(anydesk|teamviewer|rustdesk|screenconnect|connectwisecontrol|atera|splashtop)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)