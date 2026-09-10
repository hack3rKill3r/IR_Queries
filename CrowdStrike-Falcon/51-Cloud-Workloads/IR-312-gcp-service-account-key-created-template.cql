// IR-312 - GCP Service Account Key Creation (Template)
// Requires Google Cloud Audit Logs in Falcon NG-SIEM.
#Vendor=/google/i event.action=/serviceAccountKeys\.create|CreateServiceAccountKey/i
| table([@timestamp,user.name,source.ip,event.action,resource.name],limit=20000)