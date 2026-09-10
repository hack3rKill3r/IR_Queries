// IR-372 - Split/Multipart Archive Creation
#event_simpleName=ProcessRollup2
FileName=/^(7z|7za|7zz|rar|winrar)\.exe$/i
CommandLine=/\s-v\d+[kmg]?\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)