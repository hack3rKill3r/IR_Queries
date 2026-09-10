// IR-228 - NTDS Access via Shadow Copy References
// Purpose: Identify command lines combining NTDS paths and shadow-copy paths.
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
CommandLine=/(ntds\.dit.*HarddiskVolumeShadowCopy|HarddiskVolumeShadowCopy.*ntds\.dit)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)