# IR-004 - Search for a Specific Executable
# Replace malware.exe.
#event_simpleName=ProcessRollup2
FileName="malware.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)