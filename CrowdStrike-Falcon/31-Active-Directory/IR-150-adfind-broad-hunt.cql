// IR-150 - ADFind Broad Hunt
// Purpose: Identify ADFind by filename, path, or command-line reference.
#event_simpleName=ProcessRollup2
(FileName=/adfind/i OR FilePath=/adfind/i OR CommandLine=/adfind/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)