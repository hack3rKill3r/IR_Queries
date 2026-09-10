// IR-324 - Defender Exclusion Changes
// Purpose: Identify additions or changes to Defender exclusions.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(Add-MpPreference|Set-MpPreference).*(ExclusionPath|ExclusionProcess|ExclusionExtension)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)