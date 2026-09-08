// IR-037 - Common Discovery Commands
// Purpose: Broad hunt for common hands-on-keyboard discovery utilities.
#event_simpleName=ProcessRollup2
FileName=/^(whoami|hostname|systeminfo|ipconfig|arp|route|netstat|tasklist|quser|qwinsta)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)