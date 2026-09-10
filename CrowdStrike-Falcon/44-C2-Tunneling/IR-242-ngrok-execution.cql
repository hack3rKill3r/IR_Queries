// IR-242 - ngrok Execution
// Purpose: Identify ngrok usage for tunneling or remote access.
// MITRE ATT&CK: T1572
#event_simpleName=ProcessRollup2
(FileName=/^ngrok(2)?\.exe$/i OR CommandLine=/\bngrok\b/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)