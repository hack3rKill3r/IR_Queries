# IR-006 - Executables from AppData
#event_simpleName=ProcessRollup2
FilePath=/\\AppData\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)