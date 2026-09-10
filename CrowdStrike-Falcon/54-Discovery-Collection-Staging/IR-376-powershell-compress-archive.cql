// IR-376 - PowerShell Compress-Archive
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/Compress-Archive/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)