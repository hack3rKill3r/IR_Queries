// IR-311 - Azure Key Vault Access Changes (Template)
#Vendor=/microsoft/i
event.action=/(vaults.*(write|delete)|accessPolicies.*write|roleAssignments.*write)/i
resource.type=/KeyVault|vault/i
| table([@timestamp,user.name,source.ip,event.action,resource.name],limit=20000)