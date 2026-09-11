// IR-443 - Java/Tomcat Spawning Shell
// Purpose: Identify java.exe spawning command interpreters on application servers.
// MITRE ATT&CK: T1505.003
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(java|javaw)\.exe$/i
FileName=/^(cmd|powershell|pwsh|sh|bash)\.exe$|^(sh|bash)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)