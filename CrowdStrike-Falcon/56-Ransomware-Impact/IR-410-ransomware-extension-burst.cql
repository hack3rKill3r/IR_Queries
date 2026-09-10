// IR-410 - Ransomware Extension Burst
// Purpose: Identify large bursts of writes with the same extension.
// MITRE ATT&CK: T1486
#event_simpleName=/FileWritten$/
| regex("\.(?<Ext>[A-Za-z0-9_-]{2,16})$",field=TargetFileName,strict=false)
| bucket(span=5m)
| groupBy([ComputerName,Ext,_bucket],function=[count(as=Writes),collect([ContextBaseFileName])],limit=max)
| Writes>500
| sort(Writes,order=desc)