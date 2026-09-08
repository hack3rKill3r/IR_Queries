# IR-010 - Encoded PowerShell
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/\s-(e|enc|encoded|encodedcommand)\s/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)