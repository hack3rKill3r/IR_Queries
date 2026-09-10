// IR-320 - Cloud / Container IR Super Query
// Broad first-pass endpoint hunt plus cloud-log template patterns.
(
 #event_simpleName=ProcessRollup2
 (
  (FileName=/^docker$/i CommandLine=/(--privileged|--pid[ =]host|--net[ =]host|--cap-add|\/var\/run\/docker\.sock)/i)
  OR
  (FileName=/^kubectl$/i CommandLine=/(\bexec\b|\bsecrets?\b|create.*token|port-forward)/i)
 )
)
OR
(
 (#Vendor=/aws/i event.action=/(CreateAccessKey|StopLogging|DeleteTrail|AssumeRole|Attach.*Policy|PutBucketPolicy)/i)
 OR (#Vendor=/microsoft/i event.action=/(roleAssignments.*write|securityRules.*write|vaults.*delete)/i)
 OR (#Vendor=/google/i event.action=/(CreateServiceAccountKey|SetIamPolicy|DeleteSink)/i)
)
| table([@timestamp,#Vendor,ComputerName,UserName,user.name,source.ip,FileName,CommandLine,event.action,resource.name],limit=20000)