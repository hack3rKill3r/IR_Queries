# IR-011 - PowerShell Download Activity
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(Invoke-WebRequest|iwr|wget|curl|DownloadString|DownloadFile|Net\.WebClient)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)