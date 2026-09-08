# IR-007 - Executables from Temp
#event_simpleName=ProcessRollup2
FilePath=/\\Temp\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)