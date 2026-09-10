// IR-183 - Office -> LOLBin
// Purpose: Identify Office spawning high-risk proxy execution or download utilities.
// MITRE ATT&CK: T1204.002 / T1218
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(winword|excel|powerpnt|outlook)\.exe$/i
FileName=/^(rundll32|regsvr32|certutil|bitsadmin|msiexec)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)