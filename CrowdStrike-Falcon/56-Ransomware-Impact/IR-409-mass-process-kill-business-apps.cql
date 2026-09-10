// IR-409 - Mass Process Kill of Business Apps
// Purpose: Identify taskkill against common applications frequently terminated before encryption.
// MITRE ATT&CK: T1489
#event_simpleName=ProcessRollup2
FileName="taskkill.exe"
CommandLine=/(sql|oracle|outlook|excel|word|veeam|backup|exchange|vmware|sap)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)