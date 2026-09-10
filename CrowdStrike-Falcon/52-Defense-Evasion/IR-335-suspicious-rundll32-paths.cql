// IR-335 - Rundll32 Loading from User-Writable Paths
// MITRE ATT&CK: T1218.011
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
CommandLine=/(\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\).*(\.dll|\.cpl)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData],limit=20000)