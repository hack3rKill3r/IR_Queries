// IR-308 - AWS AssumeRole Activity (Template)
#Vendor=/aws/i event.action="AssumeRole"
| groupBy([user.name,target.resource.name,source.ip],function=[count(as=AssumeRoleEvents),collect([@timestamp,aws.region,userAgent])],limit=max)
| sort(AssumeRoleEvents,order=desc)