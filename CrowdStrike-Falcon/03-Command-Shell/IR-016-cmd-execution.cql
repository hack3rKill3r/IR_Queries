# IR-016 - CMD Execution
#event_simpleName=ProcessRollup2
FileName="cmd.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)