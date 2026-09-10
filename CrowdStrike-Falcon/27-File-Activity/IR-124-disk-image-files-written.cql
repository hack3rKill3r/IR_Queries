// IR-124 - ISO / VHD / VHDX Files Written
// Purpose: Identify disk-image/container files that can be used for staging or payload delivery.
#event_simpleName=/FileWritten$/
TargetFileName=/\.(iso|vhd|vhdx)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)