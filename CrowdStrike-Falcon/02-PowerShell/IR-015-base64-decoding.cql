# IR-015 - Base64 Decoding
#event_simpleName=ProcessRollup2
CommandLine=/(FromBase64String|EncodedCommand)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)