// IR-406 - Stop/Delete Backup Software Services
// Purpose: Identify service control against common backup products.
// MITRE ATT&CK: T1489
#event_simpleName=ProcessRollup2
FileName=/^(sc|net|net1)\.exe$/i
CommandLine=/(stop|delete).*(veeam|acronis|commvault|rubrik|cohesity|backup|sql|exchange)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)