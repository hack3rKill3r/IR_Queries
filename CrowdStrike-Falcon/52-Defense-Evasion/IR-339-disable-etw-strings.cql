// IR-339 - ETW / Telemetry Bypass Strings
// Purpose: Identify command lines referencing common ETW patch/bypass concepts.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(EtwEventWrite|ETW.*patch|EventWrite.*ret|ntdll.*EtwEventWrite)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)