// IR-250 - Sliver C2 String Indicators
// Purpose: Hunt for common Sliver process/command-line references.
// MITRE ATT&CK: T1071
#event_simpleName=ProcessRollup2
(FileName=/sliver/i OR CommandLine=/(sliver|mtls|wg-port|multiplayer)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)