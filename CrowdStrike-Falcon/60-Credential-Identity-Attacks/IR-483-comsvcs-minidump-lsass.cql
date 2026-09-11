// IR-483 - Comsvcs MiniDump LSASS
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
CommandLine=/comsvcs\.dll.*MiniDump.*lsass|lsass.*comsvcs\.dll.*MiniDump/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData],limit=20000)