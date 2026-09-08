# IR-013 - PowerShell Execution Policy Bypass
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(ExecutionPolicy\s+Bypass|-ep\s+bypass|bypass)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)