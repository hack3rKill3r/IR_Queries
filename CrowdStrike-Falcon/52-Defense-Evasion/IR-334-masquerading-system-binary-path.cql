// IR-334 - System Binary Masquerading by Path
// Purpose: Identify common Windows system binary names executing outside expected Windows directories.
// MITRE ATT&CK: T1036
#event_simpleName=ProcessRollup2
FileName=/^(svchost|lsass|services|winlogon|csrss|smss|wininit|conhost)\.exe$/i
FilePath!=/\\Windows\\(System32|SysWOW64)\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)