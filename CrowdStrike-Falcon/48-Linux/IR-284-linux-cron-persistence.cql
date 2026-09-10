// IR-284 - Linux Cron Persistence
// Purpose: Identify cron/crontab activity that may establish persistence.
// MITRE ATT&CK: T1053.003
event_platform=Lin
#event_simpleName=ProcessRollup2
(FileName=/^(crontab|cron|crond)$/i OR CommandLine=/(\/etc\/cron\.|@reboot)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)