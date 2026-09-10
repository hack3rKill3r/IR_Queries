// IR-337 - Falcon Process Handle Operation Detections
// Purpose: Review Falcon telemetry for suspicious cross-process handle operations.
// MITRE ATT&CK: T1055 / T1003.001
#event_simpleName=FalconProcessHandleOpDetectInfo
| table([@timestamp,ComputerName,UserName,FileName,ImageFileName,TargetImageFileName,CommandLine,TargetProcessId,ContextProcessId],limit=20000)