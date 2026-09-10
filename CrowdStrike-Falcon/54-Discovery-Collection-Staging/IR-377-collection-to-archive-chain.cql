// IR-377 - Collection -> Archive Chain
correlate(
 collection:{#event_simpleName=ProcessRollup2 FileName=/^(robocopy|xcopy|cmd|powershell|pwsh)\.exe$/i CommandLine=/(\\\\|Get-ChildItem|\bdir\b|copy|robocopy|xcopy)/i} include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
 archive:{#event_simpleName=ProcessRollup2 FileName=/^(7z|7za|7zz|rar|winrar|tar|powershell|pwsh)\.exe$/i CommandLine=/(7z|rar|tar|Compress-Archive)/i | aid <=> collection.aid | UserName <=> collection.UserName} include:[aid,ComputerName,UserName,FileName,CommandLine],
 sequence=true,within=60m)