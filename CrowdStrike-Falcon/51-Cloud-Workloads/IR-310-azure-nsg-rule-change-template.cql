// IR-310 - Azure NSG Rule Changes (Template)
#Vendor=/microsoft/i event.dataset=/azure.*activity/i
event.action=/(networkSecurityGroups.*securityRules.*(write|delete)|networkSecurityGroups\/write)/i
| table([@timestamp,user.name,source.ip,event.action,resource.name],limit=20000)