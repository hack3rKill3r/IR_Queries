# IR-008 - Executables from ProgramData
#event_simpleName=ProcessRollup2
FilePath=/\\ProgramData\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)