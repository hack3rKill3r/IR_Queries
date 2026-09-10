// IR-369 - Email Data File Collection
#event_simpleName=ProcessRollup2
CommandLine=/\.(pst|ost)\b|Outlook Files|AppData\\Local\\Microsoft\\Outlook/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)