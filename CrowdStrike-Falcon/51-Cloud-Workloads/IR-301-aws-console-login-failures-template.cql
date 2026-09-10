// IR-301 - AWS Console Login Failures (Template)
// Requires AWS CloudTrail in Falcon NG-SIEM; normalize fields to your parser.
#Vendor=/aws/i event.action="ConsoleLogin" outcome=/fail/i
| groupBy([user.name,source.ip],function=[count(as=Failures),collect([@timestamp,userAgent,errorCode])],limit=max)
| sort(Failures,order=desc)