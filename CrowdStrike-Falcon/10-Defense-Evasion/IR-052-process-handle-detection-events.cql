// IR-052 - Falcon Process Handle Detection Events
// Purpose: Surface Falcon process-handle operation detections for review of suspicious process access.
#event_simpleName=FalconProcessHandleOpDetectInfo
| table([@timestamp,ComputerName,UserName,FileName,CommandLine,TargetProcessId,ContextProcessId], limit=20000)