// IR-126 - Removable Media File Writes
// Purpose: Identify file-write activity to removable storage.
#event_simpleName=/FileWritten$/
(IsOnRemovableDisk=1 OR DiskParentDeviceInstanceId="USB*")
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,DiskParentDeviceInstanceId,ContextProcessId], limit=20000)