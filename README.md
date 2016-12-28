# Manage-Firewall
Creates bulk Windows Firewall rules targeting all executables in specified directories

<#
	.SYNOPSIS
		Creates bulk Windows Firewall rules targeting all executables in specified directories
	
	.DESCRIPTION	
		Allows the user to create Windows Firewall rules that apply to all executables in the specified directory.  

		Additionally allows the user to configure the default firewall action for all traffic (block/allow).
	
	.PARAMETER TargetDirectories
		The firewall rules will target all executables located within the specified directories.  
	
	.PARAMETER TargetExecutables
		Specify which stand-alone executables to target with this firewall rule.
	
	.PARAMETER BlockOrAllow
		Specifies the desired firewall action (BLOCK or ALLOW)
	
	.PARAMETER Direction
		Specifies the desired direction for the firewall rule (INBOUND, OUTBOUND or BOTH)
	
	.PARAMETER SetOutboundDefault
		This switch allows the user to set the default outbound rule for all network communications on the host for all Windows Firewall profiles.
	
	.PARAMETER SetInboundDefault
		This switch allows the user to set the default inbound rule for all network communications on the host for all Windows Firewall profiles.
	
	.EXAMPLE
		Manage-Firewall -TargetDirectories 'c:\Program Files (x86)\' -BlockOrAllow Block -Direction Both

	.NOTES
		FOLDER MODE:  Creates rules for each EXE in the specifieid folder

		PORT MODE:  Creates rules for open/closed ports

		PROFILE MODE:  Sets default inbound/outbound rules for all profiles

		SHOW MODE:  Shows all current Firewall Rules
