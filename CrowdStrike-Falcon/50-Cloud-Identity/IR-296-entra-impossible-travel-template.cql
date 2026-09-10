// IR-296 - Entra ID Geo/Impossible-Travel Pivot (Template)
// Purpose: Surface users authenticating from multiple countries/regions in the selected time window.
// NOTE: Requires Entra sign-in logs and parser-specific geo fields.
#Vendor="microsoft"
#event.dataset=/signin/i
user.name=*
source.geo.country=*
| groupBy([user.name], function=[count(source.geo.country,distinct=true,as=Countries),collect([source.ip,source.geo.country,@timestamp])], limit=max)
| Countries>1
| sort(Countries, order=desc)