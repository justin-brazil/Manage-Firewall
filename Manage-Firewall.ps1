#####################SCRIPT_CONTROLS##
#!#Name:  FUNCTION:  Manage-Firewall
#!#Author:  Justin Brazil
#!#Description:  Creates firewall rules corresponding to all EXEs living in one or more folders
#!#Tags:  Manage-Firewall,Firewall,Net,Rule,Fire Wall,IP,Inbound,Outbound,Port,Allob,Block,Deny,TCP,IP,TCP/IP,Traffic,Network,Security
#!#Type: Function, Script
#!#Product:  PowerShell,Manage-Firewall
#!#Modes: Scripting
#!#Notes:  See GitHub page for latest updates
#!#Link:  https://github.com/justin-brazil/Manage-Firewall
#!#Group:  Windows OS Utilities
#!#Special:  
####################/SCRIPT_CONTROLS##

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
#>
function Manage-Firewall
{
	param
	(
		[Parameter(ParameterSetName = 'EditRules',
				   HelpMessage = 'Target All EXEs in Specified Directory')]
		[array]$TargetDirectories,
		[Parameter(ParameterSetName = 'EditRules',
				   HelpMessage = 'Target individual EXEs')]
		[array]$TargetExecutables,
		[Parameter(ParameterSetName = 'EditRules',
				   Mandatory = $true,
				   HelpMessage = 'Specify Desired Firewall Action BLOCK or ALLOW')]
		[ValidateSet('Allow', 'Block')]
		[string]$BlockOrAllow,
		[Parameter(ParameterSetName = 'EditRules',
				   Mandatory = $true,
				   HelpMessage = 'Specify Direction of INBOUND, OUTBOUND or BOTH')]
		[ValidateSet('Inbound', 'Outbound', 'Both')]
		[string]$Direction,
		[Parameter(ParameterSetName = 'EditProfile',
				   HelpMessage = 'Specify Default ALLOW/BLOCK for all Outbound Connections for All Profiles')]
		[Parameter(ParameterSetName = 'EditRules',
				   Mandatory = $false,
				   HelpMessage = 'Specify Default ALLOW/BLOCK for all Outbound Connections for All Profiles')]
		[ValidateSet('Allow', 'Block')]
		[string]$SetOutboundDefault,
		[Parameter(ParameterSetName = 'EditProfile',
				   HelpMessage = 'Specify Default ALLOW/BLOCK for all Inbound Connections for All Profiles')]
		[Parameter(ParameterSetName = 'EditRules',
				   Mandatory = $false,
				   HelpMessage = 'Specify Default ALLOW/BLOCK for all Outbound Connections for All Profiles')]
		[ValidateSet('Allow', 'Block')]
		[string]$SetInboundDefault
	)
	
	######################### SET SCRIPT VARIABLES
	
	$TARGET_EXE_DISPLAY_GROUP = 'Manage-Firewall (PowerShell)'

	$ORIGINAL_FIREWALL_RULES = @()
	$REPORT_DISABLED_RULES = @()
	$REPORT_CREATED_RULES = @()
	
	######################### CREATE OBJECT CONTAINING ORIGINAL FIREWALL RULES
	
	$ORIGINAL_FIREWALL_PROFILE_STATES = Get-NetFirewallProfile -All | Select Name, DefaultInboundAction, DefaultOutboundAction
	
	
	$ORIGINAL_FIREWALL_RULES = ForEach ($ORIGINAL_FIREWALL_RULE in (Get-NetFirewallRule))
	{
		$TEMP_PROGRAM = $NULL
		$TEMP_OBJECT = $NULL		#OBJECT CONTAINING EXISTING FIREWALL RULES
		
		[string]$TEMP_PROGRAM = ($ORIGINAL_FIREWALL_RULE | Get-NetFirewallApplicationFilter).Program
		if ($TEMP_PROGRAM -like '*%*') { [string]$TEMP_PROGRAM = [System.Environment]::ExpandEnvironmentVariables($TEMP_PROGRAM) }
		
		
		$TEMP_OBJECT = New-Object -TypeName PSCustomObject
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Name –Value $ORIGINAL_FIREWALL_RULE.Name
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name DisplayName –Value $ORIGINAL_FIREWALL_RULE.DisplayName
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Description –Value $ORIGINAL_FIREWALL_RULE.Description
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name DisplayGroup –Value $ORIGINAL_FIREWALL_RULE.DisplayGroup
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Direction –Value $ORIGINAL_FIREWALL_RULE.Direction
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Action –Value $ORIGINAL_FIREWALL_RULE.Action
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Enabled –Value $ORIGINAL_FIREWALL_RULE.Enabled
		$TEMP_OBJECT | Add-Member –MemberType NoteProperty –Name Program –Value $TEMP_PROGRAM
		
		$TEMP_OBJECT
	}
	
	######################### DEFAULT INBOUNC/OUTBOUND RULES
	
	if ($SetOutboundDefault)
	{
		Set-NetFirewallProfile -All -DefaultOutboundAction $SetOutboundDefault
	}
	
	if ($SetInboundDefault)
	{
		Set-NetFirewallProfile -All -DefaultInboundAction $SetInboundDefault
	}
	
	
	################################################# ENUMERATE TARGET EXECUTABLES
	
	if (($TargetDirectories) -or ($TargetExecutables))
	{
		$EXE_FILES = @()
		$EXE_FILES =
		&{
			$TEMP_EXEFILES = @()
			
			if ($TARGETDIRECTORIES)
			{
				ForEach ($DIRECTORY in $TARGETDIRECTORIES)
				{
					if (Test-Path $DIRECTORY)
					{
						$TEMP_EXEFILES += Get-ChildItem $DIRECTORY -recurse | Where { ($_.Extension -eq '.exe') -and ($_.Name -notlike '') }
					}
				}
			}
			
			if ($TargetExecutables)
			{
				ForEach ($EXECUTABLE in $TARGETEXECUTABLES)
				{
					if (Test-Path $EXECUTABLE)
					{
						$TEMP_EXEFILES += Get-ChildItem $EXECUTABLE
					}
				}
			}
			
			$TEMP_EXEFILES
		}
	}
	
	################################################# DISABLES EXISTING RULES TARGETING SAME EXES
	
	ForEach ($ORIGINAL_RULE in ($ORIGINAL_FIREWALL_RULES | Where { $_.Enabled -eq $True }))
	{
		if ($EXE_FILES.FullName -contains $ORIGINAL_RULE.Program)
		{
			Disable-NetFirewallRule -Name $ORIGINAL_RULE.Name
			$REPORT_DISABLED_RULES += $ORIGINAL_RULE
		}
	}
	
	################################################ CREATE FIREWALL RULE FOR EACH TARGET EXE
	
	ForEach ($TARGET_EXE in $EXE_FILES)
	{
		if (($Direction -eq "Inbound") -or ($Direction -eq "Outbound"))
		{
			New-NetFirewallRule -Program $TARGET_EXE.FullName -DisplayName $TARGET_EXE.Name -profile Any -Group $TARGET_EXE_DISPLAY_GROUP -Action $BlockOrAllow -Direction $Direction -Enabled True -Description $TARGET_EXE.FullName
		}
		
		if ($Direction -eq "Both")
		{
			New-NetFirewallRule -Program $TARGET_EXE.FullName -DisplayName $TARGET_EXE.Name -profile Any -Group $TARGET_EXE_DISPLAY_GROUP -Action $BlockOrAllow -Direction "Inbound" -Enabled True -Description $TARGET_EXE.FullName
			New-NetFirewallRule -Program $TARGET_EXE.FullName -DisplayName $TARGET_EXE.Name -profile Any -Group $TARGET_EXE_DISPLAY_GROUP -Action $BlockOrAllow -Direction "Outbound" -Enabled True -Description $TARGET_EXE.FullName
		}
	}
}
