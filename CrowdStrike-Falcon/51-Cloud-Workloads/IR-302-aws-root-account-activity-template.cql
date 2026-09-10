// IR-302 - AWS Root Account Activity (Template)
// Purpose: Surface root identity use. Requires CloudTrail.
#Vendor=/aws/i user.type=/Root/i
| table([@timestamp,user.name,source.ip,event.action,aws.region,userAgent],limit=20000)