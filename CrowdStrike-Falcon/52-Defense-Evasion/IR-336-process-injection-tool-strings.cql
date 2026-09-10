// IR-336 - Process Injection Tool Strings
// Purpose: Hunt for common injection terminology/tooling in command lines.
// MITRE ATT&CK: T1055
#event_simpleName=ProcessRollup2
CommandLine=/(processinject|injector|reflective.*dll|CreateRemoteThread|WriteProcessMemory|QueueUserAPC|NtMapViewOfSection)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)