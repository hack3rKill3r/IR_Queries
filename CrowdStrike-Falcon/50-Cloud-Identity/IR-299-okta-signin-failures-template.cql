// IR-299 - Okta Sign-in Failures (Template)
// Purpose: Identify failed Okta authentication activity after Okta System Log ingestion.
// NOTE: Field names vary by parser/source. Map placeholders to your tenant.
#Vendor="okta"
event.type=/user\.session|authentication/i
outcome=/fail/i
| groupBy([user.name,source.ip], function=[count(as=Failures),collect([@timestamp,event.type,reason])], limit=max)
| sort(Failures, order=desc)