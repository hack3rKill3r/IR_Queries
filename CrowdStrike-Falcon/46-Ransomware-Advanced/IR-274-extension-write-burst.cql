// IR-274 - Extension Write Burst
// Purpose: Identify rapid creation of files sharing the same extension, useful for ransomware encryption hunting.
#event_simpleName=/FileWritten$/
| regex("\\.(?<Ext>[A-Za-z0-9]{2,12})$", field=TargetFileName, strict=false)
| bucket(span=5m)
| groupBy([ComputerName,Ext,_bucket], function=[count(as=Writes),collect([ContextBaseFileName])], limit=max)
| Writes>500
| sort(Writes, order=desc)