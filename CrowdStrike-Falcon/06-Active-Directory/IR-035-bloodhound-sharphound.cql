// IR-035 - BloodHound / SharpHound Indicators
// Purpose: Identify common BloodHound/SharpHound collection strings.
// MITRE ATT&CK: T1087.002 / T1069.002
#event_simpleName=ProcessRollup2
(FileName=/(sharphound|bloodhound)/i OR CommandLine=/(sharphound|bloodhound|collectionmethod)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)