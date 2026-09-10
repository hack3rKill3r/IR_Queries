// IR-304 - AWS IAM Policy / Privilege Changes (Template)
#Vendor=/aws/i event.action=/(Attach.*Policy|Put.*Policy|CreatePolicyVersion|SetDefaultPolicyVersion|AddUserToGroup)/i
| table([@timestamp,user.name,target.user.name,source.ip,event.action,aws.region],limit=20000)