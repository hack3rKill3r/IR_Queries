// IR-025 - WinRM / WSMProvHost Activity
// Purpose: Identify commands executed through Windows Remote Management.
// MITRE ATT&CK: T1021.006
#event_simpleName=ProcessRollup2
(FileName="wsmprovhost.exe" OR ParentBaseFileName="wsmprovhost.exe")
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)