// IR-371 - Password-Protected Archive Staging
#event_simpleName=ProcessRollup2
FileName=/^(7z|7za|7zz|rar|winrar)\.exe$/i
CommandLine=/\s-p\S+/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)