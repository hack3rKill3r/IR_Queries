// IR-375 - XCOPY Bulk Collection
#event_simpleName=ProcessRollup2
FileName="xcopy.exe"
CommandLine=/(\\\\|\/E|\/S|\/H|\/C|\/I)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)