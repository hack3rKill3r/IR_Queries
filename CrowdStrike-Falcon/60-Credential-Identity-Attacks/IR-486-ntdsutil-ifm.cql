// IR-486 - NTDSUtil IFM Extraction
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
FileName="ntdsutil.exe"
CommandLine=/(activate\s+instance\s+ntds|\bifm\b|create\s+full)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)