// IR-149 - LDAP / Active Directory Tooling
// Purpose: Identify native AD and LDAP administration/enumeration utilities.
#event_simpleName=ProcessRollup2
FileName=/^(ldp|ldifde|csvde|dsquery|dsget|dsmod|dsadd)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)