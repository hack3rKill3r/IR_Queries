# IR-020 - RDP Clipboard
#event_simpleName=ProcessRollup2
FileName="rdpclip.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)