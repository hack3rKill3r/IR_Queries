// IR-309 - Azure Destructive Resource Actions (Template)
// Requires Azure Activity logs in Falcon NG-SIEM.
#Vendor=/microsoft/i event.dataset=/azure.*activity/i
event.action=/(delete|remove|purge)/i
| table([@timestamp,user.name,source.ip,event.action,resource.name,resource.type],limit=20000)