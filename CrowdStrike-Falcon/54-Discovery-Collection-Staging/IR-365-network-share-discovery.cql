// IR-365 - Network Share Discovery
#event_simpleName=ProcessRollup2
((FileName=/^(net|net1)\.exe$/i CommandLine=/\bview\b|\buse\b/i) OR CommandLine=/(Get-SmbShare|Get-SmbMapping|\\\\[^\\\s]+\\)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)