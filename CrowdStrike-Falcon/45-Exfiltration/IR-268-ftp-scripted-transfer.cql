// IR-268 - FTP Scripted Transfer
// Purpose: Identify ftp.exe command lines suggesting scripted or noninteractive transfer.
// MITRE ATT&CK: T1048
#event_simpleName=ProcessRollup2
FileName="ftp.exe"
CommandLine=/(-s:|open\s|put\s|mput\s)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)