// IR-307 - AWS S3 Policy / ACL Changes (Template)
#Vendor=/aws/i event.action=/(PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|PutBucketPublicAccessBlock)/i
| table([@timestamp,user.name,source.ip,event.action,aws.region,requestParameters],limit=20000)