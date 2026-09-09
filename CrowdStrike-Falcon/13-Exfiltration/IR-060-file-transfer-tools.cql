// IR-060 - File Transfer / Exfiltration Utilities
// Purpose: Identify common utilities capable of transferring staged data.
// MITRE ATT&CK: T1048 / T1567
#event_simpleName=ProcessRollup2
FileName=/^(rclone|winscp|winscp\.com|filezilla|curl|wget|ftp)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)