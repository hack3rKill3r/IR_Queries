# IR-009 - All PowerShell
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)