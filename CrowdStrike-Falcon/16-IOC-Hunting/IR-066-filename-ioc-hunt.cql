// IR-066 - Filename IOC Hunt
// Replace IOC_FILE with the target filename.
#event_simpleName=ProcessRollup2
FileName="IOC_FILE"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)