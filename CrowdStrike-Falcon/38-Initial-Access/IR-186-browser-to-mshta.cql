// IR-186 - Browser -> MSHTA
// Purpose: Identify browser-launched mshta execution.
// MITRE ATT&CK: T1218.005
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(chrome|msedge|firefox|iexplore|brave)\.exe$/i
FileName="mshta.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)