// IR-314 - GCP Logging / Audit Tampering (Template)
#Vendor=/google/i event.action=/(DeleteSink|UpdateSink|logging.*delete|logging.*update)/i
| table([@timestamp,user.name,source.ip,event.action,resource.name],limit=20000)