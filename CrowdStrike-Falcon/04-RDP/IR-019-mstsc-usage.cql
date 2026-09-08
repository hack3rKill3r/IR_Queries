# IR-019 - MSTSC Usage
# Review CommandLine for /v:SERVER or /v:IP destinations.
#event_simpleName=ProcessRollup2
FileName="mstsc.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)