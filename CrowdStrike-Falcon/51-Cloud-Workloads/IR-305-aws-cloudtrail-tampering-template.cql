// IR-305 - AWS CloudTrail Tampering (Template)
// MITRE ATT&CK: T1562.008
#Vendor=/aws/i event.action=/(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors)/i
| table([@timestamp,user.name,source.ip,event.action,aws.region,userAgent],limit=20000)