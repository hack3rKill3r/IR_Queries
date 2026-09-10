// IR-373 - PST Export / Mail Collection Strings
#event_simpleName=ProcessRollup2
CommandLine=/(New-MailboxExportRequest|Export-Mailbox|ContentSearch|\.pst)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)