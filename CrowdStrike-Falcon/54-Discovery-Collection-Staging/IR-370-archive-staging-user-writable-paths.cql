// IR-370 - Archive Staging in User-Writable Paths
#event_simpleName=ProcessRollup2
FileName=/^(7z|7za|7zz|rar|winrar|tar)\.exe$/i
CommandLine=/(\\Temp\\|\\AppData\\|\\Desktop\\|\\Downloads\\)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)