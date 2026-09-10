// IR-368 - Browser History/Cookie Collection References
#event_simpleName=ProcessRollup2
CommandLine=/(History|Cookies|Web Data|Login Data|places\.sqlite|cookies\.sqlite)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)