// IR-039 - Broad LOLBin Hunt
// Purpose: Surface execution of frequently abused Windows-native binaries.
#event_simpleName=ProcessRollup2
FileName=/^(certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|msbuild|installutil|wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)