// IR-247 - Chisel Execution
// Purpose: Identify Chisel tunneling/proxy activity.
// MITRE ATT&CK: T1572 / T1090
#event_simpleName=ProcessRollup2
(FileName=/^chisel(\.exe)?$/i OR CommandLine=/\bchisel\b/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)