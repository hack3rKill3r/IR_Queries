// IR-193 - Script Host Executing from Temp/AppData
// Purpose: Identify wscript/cscript executing scripts from user-writable paths.
// MITRE ATT&CK: T1059.005
#event_simpleName=ProcessRollup2
FileName=/^(wscript|cscript)\.exe$/i
CommandLine=/(\\Temp\\|\\AppData\\|\\Downloads\\)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)