// IR-446 - IIS Worker Spawning Rundll32
// Purpose: Identify suspicious DLL execution from IIS worker processes.
#event_simpleName=ProcessRollup2
ParentBaseFileName="w3wp.exe"
FileName="rundll32.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)