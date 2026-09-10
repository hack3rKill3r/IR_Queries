// IR-269 - Removable Media Staging
// Purpose: Identify archive or document writes to removable storage.
#event_simpleName=/FileWritten$/
(IsOnRemovableDisk=1 OR DiskParentDeviceInstanceId="USB*")
TargetFileName=/\.(zip|7z|rar|docx|xlsx|pdf|pst|ost|csv)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,DiskParentDeviceInstanceId], limit=20000)