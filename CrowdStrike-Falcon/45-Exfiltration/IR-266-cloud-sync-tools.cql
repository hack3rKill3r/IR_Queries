// IR-266 - Cloud Sync / Transfer Tools
// Purpose: Identify common sync or upload utilities used during exfiltration.
#event_simpleName=ProcessRollup2
FileName=/(rclone|megasync|megacmd|dropbox|onedrive|winscp|filezilla|azcopy)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)