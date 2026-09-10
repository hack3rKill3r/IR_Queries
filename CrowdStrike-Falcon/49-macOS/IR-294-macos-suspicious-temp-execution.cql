// IR-294 - macOS Execution from Temporary Paths
// Purpose: Identify execution from /tmp or /private/tmp.
event_platform=Mac
#event_simpleName=ProcessRollup2
FilePath=/^\/(tmp|private\/tmp|var\/tmp)\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)