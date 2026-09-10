// IR-322 - Security Service Stop/Delete
// Purpose: Identify service-control commands targeting common security products.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
FileName=/^(sc|net|net1)\.exe$/i
CommandLine=/(stop|delete).*(defender|sense|falcon|crowdstrike|sentinel|sophos|carbonblack|cbdefense|elastic|symantec|mcafee)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)