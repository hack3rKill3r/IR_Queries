// IR-353 - ComputerDefaults UAC Bypass Indicators
// MITRE ATT&CK: T1548.002
#event_simpleName=ProcessRollup2
(CommandLine=/(ms-settings\\shell\\open\\command|DelegateExecute)/i OR FileName="computerdefaults.exe")
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)