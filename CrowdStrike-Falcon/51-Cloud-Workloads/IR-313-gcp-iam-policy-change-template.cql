// IR-313 - GCP IAM Policy Changes (Template)
#Vendor=/google/i event.action=/SetIamPolicy|setIamPolicy/i
| table([@timestamp,user.name,source.ip,event.action,resource.name],limit=20000)