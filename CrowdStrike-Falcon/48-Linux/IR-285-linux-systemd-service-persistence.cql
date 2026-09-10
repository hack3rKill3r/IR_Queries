// IR-285 - Linux systemd Service Persistence
// Purpose: Identify systemctl/service activity used to create or enable services.
// MITRE ATT&CK: T1543.002
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName=/^(systemctl|service)$/i
CommandLine=/(enable|start|daemon-reload)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)