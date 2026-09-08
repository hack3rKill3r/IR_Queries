# IR-005 - Search Command Lines
# Replace SEARCHTERM with any process/tool/IOC/command fragment.
# Examples: mimikatz, lsass, rclone, 10.20.30.40, Invoke-WebRequest.
#event_simpleName=ProcessRollup2
CommandLine=/SEARCHTERM/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)