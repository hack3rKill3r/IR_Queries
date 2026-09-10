// IR-182 - Office -> Script Host
// Purpose: Identify Office applications launching wscript/cscript/mshta.
// MITRE ATT&CK: T1204.002 / T1059.005 / T1218.005
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(winword|excel|powerpnt|outlook)\.exe$/i
FileName=/^(wscript|cscript|mshta)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)