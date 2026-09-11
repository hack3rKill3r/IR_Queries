// IR-470 - Remote Utilities Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/(rutserv|rfusclient|RemoteUtilities).*\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)