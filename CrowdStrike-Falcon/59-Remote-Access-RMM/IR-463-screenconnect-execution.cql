// IR-463 - ScreenConnect / ConnectWise Control Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
(FileName=/ScreenConnect.*\.exe$/i OR CommandLine=/(ScreenConnect|ConnectWise Control)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)