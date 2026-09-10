// IR-333 - Timestomping Tool/Command Strings
// Purpose: Hunt for common timestomping utilities and PowerShell timestamp manipulation.
// MITRE ATT&CK: T1070.006
#event_simpleName=ProcessRollup2
CommandLine=/(timestomp|Set-ItemProperty.*(CreationTime|LastWriteTime|LastAccessTime)|\.CreationTime\s*=|\.LastWriteTime\s*=)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)