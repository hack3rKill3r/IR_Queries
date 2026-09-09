// IR-068 - System Binary Name Outside Windows Directory
// Purpose: Find suspicious copies of common Windows system binary names.
// MITRE ATT&CK: T1036
#event_simpleName=ProcessRollup2
FileName=/^(svchost|lsass|services|csrss|smss|winlogon|wininit)\.exe$/i
FilePath!=/\\Windows\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)