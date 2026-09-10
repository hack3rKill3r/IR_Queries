// IR-287 - Linux Execution from /tmp or /var/tmp
// Purpose: Identify binaries executed from common writable temporary paths.
event_platform=Lin
#event_simpleName=ProcessRollup2
FilePath=/^\/(tmp|var\/tmp|dev\/shm)\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)