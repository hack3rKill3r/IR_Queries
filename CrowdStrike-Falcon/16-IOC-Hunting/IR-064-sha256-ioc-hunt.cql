// IR-064 - SHA256 IOC Hunt
// Replace HASH with the SHA256 indicator.
#event_simpleName=ProcessRollup2
SHA256HashData="HASH"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)