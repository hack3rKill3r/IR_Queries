// IR-295 - Entra ID Sign-in Failures (Template)
// Purpose: Identify failed Entra ID sign-ins after Entra audit/sign-in logs are ingested into Falcon Next-Gen SIEM.
// NOTE: Field names vary by parser/source. Map the placeholders below to your tenant schema.
#Vendor="microsoft"
#event.dataset=/signin/i
outcome=/fail/i
| groupBy([user.name,source.ip], function=[count(as=Failures),collect([@timestamp,reason,application])], limit=max)
| sort(Failures, order=desc)