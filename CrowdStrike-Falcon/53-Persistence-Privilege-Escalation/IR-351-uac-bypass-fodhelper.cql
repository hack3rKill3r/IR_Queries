// IR-351 - Fodhelper UAC Bypass Indicators
// Purpose: Identify registry/process patterns associated with fodhelper bypass.
// MITRE ATT&CK: T1548.002
#event_simpleName=ProcessRollup2
(CommandLine=/(ms-settings\\shell\\open\\command|DelegateExecute)/i OR FileName="fodhelper.exe")
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)