// IR-362 - Active Directory Discovery Burst
#event_simpleName=ProcessRollup2
(FileName=/^(nltest|dsquery|dsget|ldifde|csvde|net|net1)\.exe$/i OR CommandLine=/(Get-ADUser|Get-ADComputer|Get-ADGroup|Get-DomainUser|Get-DomainGroup|SharpHound|adfind)/i)
| bucket(span=10m)
| groupBy([ComputerName,UserName,_bucket],function=[count(as=ADReconEvents),collect([FileName,CommandLine])],limit=max)
| sort(ADReconEvents,order=desc)