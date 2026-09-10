// IR-361 - Reconnaissance Command Burst
#event_simpleName=ProcessRollup2
FileName=/^(whoami|hostname|systeminfo|ipconfig|arp|route|netstat|quser|qwinsta|nltest|net|net1|dsquery|nslookup)\.exe$/i
| bucket(span=10m)
| groupBy([ComputerName,UserName,_bucket],function=[count(as=ReconCommands),count(FileName,distinct=true,as=UniqueTools),collect([FileName,CommandLine])],limit=max)
| UniqueTools>=4
| sort(ReconCommands,order=desc)