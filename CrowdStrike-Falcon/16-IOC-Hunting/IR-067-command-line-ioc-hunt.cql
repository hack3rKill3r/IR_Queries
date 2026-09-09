// IR-067 - Command-Line IOC Hunt
// Replace SEARCHTERM with an escaped string or regex from the investigation.
#event_simpleName=ProcessRollup2
CommandLine=/SEARCHTERM/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)