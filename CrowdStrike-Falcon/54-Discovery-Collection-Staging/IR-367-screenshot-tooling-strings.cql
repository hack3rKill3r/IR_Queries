// IR-367 - Screenshot Collection Indicators
#event_simpleName=ProcessRollup2
CommandLine=/(screenshot|BitBlt|CopyFromScreen|Graphics\.CopyFromScreen|nircmd.*savescreenshot)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)