// IR-352 - EventVwr UAC Bypass Indicators
// MITRE ATT&CK: T1548.002
#event_simpleName=ProcessRollup2
(CommandLine=/(mscfile\\shell\\open\\command)/i OR FileName="eventvwr.exe")
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)