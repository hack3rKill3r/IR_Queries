// IR-306 - AWS Security Group Exposure Changes (Template)
#Vendor=/aws/i event.action=/(AuthorizeSecurityGroupIngress|ModifySecurityGroupRules)/i
| table([@timestamp,user.name,source.ip,event.action,aws.region,requestParameters],limit=20000)