// IR-481 - LSASS Access Broad Hunt
// Purpose: Surface process-handle telemetry involving lsass.exe.
// MITRE ATT&CK: T1003.001
#event_simpleName=FalconProcessHandleOpDetectInfo
(TargetImageFileName=/\\lsass\.exe$/i OR ImageFileName=/\\lsass\.exe$/i OR FileName=/lsass/i)
| table([@timestamp,ComputerName,UserName,FileName,ImageFileName,TargetImageFileName,CommandLine,TargetProcessId,ContextProcessId],limit=20000)