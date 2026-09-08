# IR-003 - Everything Executed by a User
# Replace USERNAME.
#event_simpleName=ProcessRollup2
UserName="USERNAME"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)