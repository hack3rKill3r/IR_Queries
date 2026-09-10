// IR-407 - Database Service Stops
// MITRE ATT&CK: T1489
#event_simpleName=ProcessRollup2
FileName=/^(sc|net|net1)\.exe$/i
CommandLine=/(stop|delete).*(MSSQL|SQLSERVERAGENT|SQLBrowser|Oracle|MySQL|PostgreSQL|MongoDB)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)