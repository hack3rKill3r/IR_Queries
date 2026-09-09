// IR-048 - Run / RunOnce Registry Persistence
// Purpose: Identify reg.exe commands referencing common Run and RunOnce persistence keys.
// MITRE ATT&CK: T1547.001
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/(CurrentVersion\\Run|CurrentVersion\\RunOnce)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)