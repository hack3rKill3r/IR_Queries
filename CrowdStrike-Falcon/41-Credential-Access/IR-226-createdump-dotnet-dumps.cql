// IR-226 - CreateDump / .NET Dump Utility
// Purpose: Identify execution of createdump.exe or similar dump tooling.
// MITRE ATT&CK: T1003
#event_simpleName=ProcessRollup2
FileName=/(createdump|dotnet-dump)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)