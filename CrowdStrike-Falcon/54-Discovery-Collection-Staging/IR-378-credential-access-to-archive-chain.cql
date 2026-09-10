// IR-378 - Credential Access -> Archive Chain
correlate(
 cred:{#event_simpleName=ProcessRollup2 CommandLine=/(lsass|ntds\.dit|secretsdump|sam.*save|security.*save|mimikatz|Rubeus.*dump)/i} include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
 archive:{#event_simpleName=ProcessRollup2 FileName=/^(7z|7za|7zz|rar|winrar|tar)\.exe$/i | aid <=> cred.aid | UserName <=> cred.UserName} include:[aid,ComputerName,UserName,FileName,CommandLine],
 sequence=true,within=120m)