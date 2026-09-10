// IR-270 - Exfiltration Super Query
// Purpose: Broad first-pass hunt for archive creation, removable media staging, and common transfer tools.
(
  #event_simpleName=ProcessRollup2
  FileName=/(7z|7za|7zz|rar|winrar|tar|rclone|winscp|winscp\.com|curl|ftp|filezilla|azcopy|megasync|megacmd)\.exe$/i
)
OR
(
  #event_simpleName=/FileWritten$/
  ((IsOnRemovableDisk=1 OR DiskParentDeviceInstanceId="USB*") OR TargetFileName=/\.(zip|7z|rar|tar|gz|tgz)$/i)
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ContextBaseFileName,ParentBaseFileName,FileName,FilePath,CommandLine,TargetFileName,FileSize,SHA256HashData], limit=20000)