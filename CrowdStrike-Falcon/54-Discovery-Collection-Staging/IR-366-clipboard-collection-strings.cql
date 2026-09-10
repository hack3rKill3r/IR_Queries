// IR-366 - Clipboard Collection Strings
#event_simpleName=ProcessRollup2
CommandLine=/(Get-Clipboard|clipboard|clip\.exe|System\.Windows\.Forms\.Clipboard)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)