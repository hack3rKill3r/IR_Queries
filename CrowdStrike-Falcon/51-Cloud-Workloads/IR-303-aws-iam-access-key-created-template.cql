// IR-303 - AWS IAM Access Key Creation (Template)
#Vendor=/aws/i event.action="CreateAccessKey"
| table([@timestamp,user.name,target.user.name,source.ip,aws.region,userAgent],limit=20000)