# IR-018 - RDP Client Activity
#event_simpleName=ProcessRollup2
(FileName="mstsc.exe" OR FileName="rdpclip.exe")
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine],limit=20000)