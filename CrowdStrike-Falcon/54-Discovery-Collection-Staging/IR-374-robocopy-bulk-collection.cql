// IR-374 - Robocopy Bulk Collection
#event_simpleName=ProcessRollup2
FileName="robocopy.exe"
CommandLine=/(\\\\|\/E|\/MIR|\/COPYALL|\/ZB)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)