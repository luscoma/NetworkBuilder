<#
Network-Script
This script builds a network 
#>

# These are top-level properties
# Which control the execution of the script
$file = "users-change.txt"							# the file to parse
$tombstone_file = "tombstone.xml"			# tombstone file
$password = "tigers234AD" | ConvertTo-SecureString -AsPlainText -Force # the password to set for all user accounts
$expiration = "5/20/2011"			        # expire on may 20 2011
$tombstone_days = 7							# number of days a user's droped class waits
$do_inheritance = $true						# Enables or disables the inhertance fix
$compare = $false							# enable compare mode by setting this to $true
$vebrose = $false							# enables vebrose mode

# Major List
$Majors = @{
	# Architecture
	"ARCH" = "ARCH";
	"ARIA" = "ARCH";
	"LAND" = "ARCH";
	"PLND" = "ARCH";
	"CPLN" = "ARCH";
	"PARC" = "ARCH";
	
	# Building Science
	"PBSC" = "BSCI";
	"BSCI" = "BSCI";
	
	# Industrial Design
	"PIND" = "INDD";
	"INDD" = "INDD";
	"GDES" = "INDD";
	
	# College of Architecture, Design, and Construction
	"CADC" = "CADC";
};

# Server Class Folder Map
$Servers = @{
<#	"ARCH" = "\\cadc12\ARCH_Classes";
	"BSCI" = "\\cadc13\BSCI_Classes";
	"INDD" = "\\cadc14\INDD_Classes";
	"CADC" = "\\cadc16\CADC_Classes"; #>
    "ARCH" = "\\localhost\SHARE\ARCH_Classes";
    "BSCI" = "\\localhost\SHARE\BSCI_Classes";
    "INDD" = "\\localhost\SHARE\INDD_Classes";
    "CADC" = "\\localhost\SHARE\CADC_Classes";
};
# LDAP Paths
#$LDAP = "DC=cadcit,DC=auburn,DC=edu";
#$DOMAIN = "CADCIT\"
#$FullDomain = "cadcit.auburn.edu"
$LDAP = "DC=test,DC=local";
$DOMAIN = "TEST\"
$FullDomain = "test.local"

# Define Helper Functions
function CreateClass($class)
{
	# Get LDAP Path
	$department = $Majors[$class.Major]
    $facname = $department + " Faculty"
	$facgroup = Get-ADGroup -Filter { name -eq $facname } -SearchBase "OU=Groups,OU=$department,$LDAP"
	$utmuser = $department + "_UTM"
	
	# Creates a new class, its folders and groups
	$cname = $class.FormattedName
    $class_fac = $cname + "_FAC"
	$classgroup = New-ADGroup $cname -Path "OU=Classes,OU=$department,$LDAP" -GroupScope "global" -WhatIf:$compare -PassThru
	$instrgroup = New-ADGroup $class_fac -Path "OU=Instructors,OU=$department,$LDAP" -GroupScope "global" -WhatIf:$compare -PassThru
	
	# Add initial groups
	Add-ADGroupMember $facgroup -members $instrgroup -WhatIf:$compare		# adds instructor group to faculty group
	Add-ADGroupMember $classgroup -members $instrgroup -WhatIf:$compare		# adds instructor group to class group
	
	# Create Folders (TODO)
	$path = join-path $Servers[$department] -ChildPath $class.FormattedName
	$assign_path = join-path $path -ChildPath "ASSIGN"
	$shared_path = join-path $path -ChildPath "SHARED"
	New-Item $path -type directory -WhatIf:$compare | out-null						# create main class path
	New-Item $assign_path -type directory -WhatIf:$compare | out-null				# create assignment folder
	New-Item $shared_path -type directory -WhatIf:$compare | out-null				# create shared folder

	# Set ACLS For Main Path
	$acl = Get-Acl $path
	$utm = CreateAccessRule $utmuser "FullControl" $false "Allow"
    $sys = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true
	$c_rule = CreateAccessRule $class.FormattedName "ReadAndExecute" $false "Allow"
	$f_rule = CreateAccessRule $class_fac "FullControl" $true "Allow"
	$acl.AddAccessRule($utm)
	$acl.AddAccessRule($sys)
	$acl.AddAccessRule($c_rule)
	$acl.AddAccessRule($f_rule)
	$acl | Set-Acl $path -WhatIf:$compare	
	
	# Adjust ACL for assign folder
	$acl = $assign_path | Get-Acl
	$class_rande = CreateAccessRule $class.FormattedName "ReadAndExecute" $false "Allow"
	$acl.SetAccessRule($class_rande)
	$acl | Set-Acl $assign_path -WhatIf:$compare
	
	# Adjust ACL for shared folder
	$acl = $shared_path | Get-Acl
	$class_full = CreateAccessRule $class.FormattedName "FullControl" $false "Allow"
	$acl.SetAccessRule($class_full)
	$acl | Set-Acl $shared_path -WhatIf:$compare
	
	$classgroup
}
function CreateAccessRule($user, $perm, $inherit, $type, $nodomain = $false) 
{
	# Build the inheritance and propagation flags
	$inheritance_flags = [System.Security.AccessControl.InheritanceFlags]"None"
	$propagation_flags = [System.Security.AccessControl.PropagationFlags]"NoPropagateInherit"
	if ($inherit -eq $true) {
		$inheritance_flags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit","ObjectInherit"
		$propagation_flags = [System.Security.AccessControl.PropagationFlags]"None"
	}
	
	# Create Permission and returns it
    $u = "$user@$FullDomain"
    if ($nodomain) { $u = $user }
	$permission = $u,$perm,$inheritance_flags, $propagation_flags, "$type"
	New-Object System.Security.AccessControl.FileSystemAccessRule $permission
}
function MoveUserClassSection($user, $drop, $add) 
{
	# Add User to New Group
    $AddClass_Department = $Majors[$add.Major]
    $AddClass_FormattedName = $add.FormattedName  # for some reason the query syntax won't allow $add.FormattedName... who knows
	$classad = Get-ADGroup -Filter { name -eq $AddClass_FormattedName } -SearchBase "OU=Classes,OU=$AddClass_Department,$LDAP"
	if ($classad -eq $null) { $classad = CreateClass($add); }				                                                            # this is just in case the class hasn't been created yet (say a new section just opened and this is the first person to be put in it in the list, and they happen to be changing sections not just a new class
	
	# Move User Folder
	$department = $Majors[$drop.Major]
	$drop_path = join-path $Servers[$department] -ChildPath $drop.FormattedName | join-path -ChildPath $user.SamAccountName
	$add_path = join-path $Servers[$department] -ChildPath $add.FormattedName
	Move-Item $drop_path -Destination $add_path -WhatIf:$compare
}
function FormatClass($class_name)
{
    $name = $class_name.Replace("_","")

	#Returns a class object from the name
	@{
		Name = $name ;
		FormattedName = [string]::Format("{0}_{1}_{2}",$name.Substring(0,4),$name.Substring(4,4),$name.Substring(8,3)) ;
		Major = $name.Substring(0,4)
	}
}
# Traps Any Errors
trap { 
	Write-Host "Error Occurred: $_"; 
	Write-Host "Terminating Execution";
	
	if ($compare -eq $false) { break; }		# In non-compare mode if a serious error occurres we dump
	else { continue; }						# if we're in comparison mode the Get-ACL will fail if the folder doesn't exist so we just truck through it
}

# Load tombstone files
$tombstones = @{}
if (Test-Path $tombstone_file) {
    $tombstones = Import-Clixml $tombstone_file
}

# This imports the csv file of users into a ready to use format
# The classes are mighty annoying since they are individual properties but we will deal with that in a a moment
Write-Host "Importing OIT User File"
$users = Import-Csv $file -Header  "Givenname","MiddleName","Surname","SamAccountName","Year","Major","Password","Class1","Class2","Class3","Class4","Class5","Class6","Class7","Class8","Class9","Class10" -Delimiter ';' | where { $Majors.ContainsKey($_.Major) } | add-member -membertype "ScriptProperty" -name Department -Value { $Majors[$this.Major] } -PassThru

# We collapse down the csv file into user and class objects and perform the necessary operations
$classes = @{}
$class_users = @{}
$start = Get-Date
Write-Host "Start" (Get-Date)
foreach ($user in $users) {
	# Lets do whats important for each user here	
	# Get the AD-User Object
	$department = $user.Department
    $name = $user.SamAccountName
	$userad = Get-ADUser -Filter { Name -eq $name } -SearchBase "OU=Students,OU=$department,$LDAP"
	if ($userad -eq $null) 					# does the user already exist?
	{
		New-ADUser $user.SamAccountName -SamAccountName $user.SamAccountName -GivenName $user.GivenName -Surname $user.Surname -AccountPassword $password -Enabled $false -ScriptPath 'SCRIPTLOGIC' -AccountExpirationDate $expiration -Path "OU=Students,OU=$department,$LDAP" -WhatIf:$compare
        $userad = Get-ADUser -Filter { Name -eq $name } -SearchBase "OU=Students,OU=$department,$LDAP"
		Write-Host "Creating a new user: " $user.SamAccountName
	}
		
	# Loop through users classes and add unique ones to our big list
	$myclasses = $user | get-member -Name "Class*" | select -ExpandProperty Definition | foreach { $_.Substring($_.IndexOf("=")+1) } | where { $_.Length -gt 1 -and $Majors.ContainsKey($_.Substring(0,4)) } | foreach { FormatClass $_ } # this is a long way of saying, for each user get the class* properties value, get anything after the equals where th 	e length > 1 character and its in our Major
	$class_names = $myclasses | foreach { $_.FormattedName }
    if ($myclasses -ne $null) {
        foreach ($class in $myclasses) {
    		if ($classes.ContainsKey($class.FormattedName) -ne $true)  {
    			Write-Host "Found New Class: " $class.Name
    			$classes.Add($class.FormattedName, $class); 
    			$t = New-Object System.Collections.ArrayList
    			$class_users.Add($class.FormattedName,$t);
    		}
    	}
    }
	
	# Get Groups and handle dropped classes
	$groups = Get-ADPrincipalGroupMembership $userad											# Retrieves the user's groups
	$group_names = $groups | select name -ExpandProperty name									# Retreives the names of all groups this user is a member of
	
	# Store list of classes user should add (aka those which were enrolled but are not currently a member)
	$added = $class_names | where { $group_names -notcontains $_  }								# Get the groups that we aren't currently in and need to be added to
    if ($added -ne $null) {
        foreach ($add in $added) {                                                              # Note these are only formatted names not full group ad objects
			$class_users[$add].Add($user.SamAccountName) | out-null
			Write-Host "Adding Class: $add for" $user.SamAccountName
		}
	}
	
	# Drop the classes that should be dropped (aka those which were a member but are no longer enrolled)
	$dropped = $groups | where { $_.name -match "\w{4}_\d{4}_\d{3}" -and $class_names -notcontains  $_.name } 							# Filter the groups by the names that don't exist anymore
    if ($dropped -ne $null) {
        foreach ($drop in $dropped) {
    		$dropad = Get-ADGroup -Filter { name -eq $drop.name } -SearchBase "OU=Classes,OU=$department,$LDAP"						# Retreives an AD Group for this class
    		Remove-ADPrincipalGroupMembership $userad -memberOf $dropad -WhatIf:$compare -Confirm:$false							# Removes the AD user from the group
    		Write-Host "Dropping Class:" $drop.name "for" $user.SamAccountName
    		
    		# Check if section was moved and not a full drop
    		$new_section = $added | where { $_ -match ($drop.name.Substring(0,8)+"*") } | select -First 1				# if any section matches the prefix sans the section number (only select 1, hopefully they dont join two sections, if so we can't help them)
    		if ($new_section -ne $null)	{																			# then lets get the class object for both the one that matched
    			MoveUserClassSection $user (FormatClass $drop.name) $classes[$new_section]								# and the dropped one and just move the users folder
    			Write-Host "Moved User Section from" $drop.name "to" $new_section
    		}
    		else {		
    			# get the class object
    			$cname = $drop.name
    		
    			# Remove the ACL 
    			$userpath = join-path $Servers[$department] -ChildPath ("$cname\"+$user.SamAccountName)
    			$acl = Get-ACL $userpath
    			$rule = $acl.Access | where { $_.IdentityReference -eq ("$DOMAIN"+$user.SamAccountName) }
                if ($rule -ne $null) { $acl.RemoveAccessRule($rule) }
    			Set-Acl $acl -Path $userpath -WhatIf:$compare
    			
    			# Hide the folder
    			$dir = Get-Item $userpath
    			$dir.Attributes = $dir.Attributes -bor [System.IO.FileAttributes]"hidden"

    			# Tombstone Folder
    			if ($tombstones.Containskey($user.SamAccountName) -ne $true) {
    				$tombstones.Add($user.SamAccountName,@{});						# Creates a tombstone for this user
    			}
    			
    			# Add a tombstone entry
    			$tombstones[$user.SamAccountName].Add($cname, (Get-Date))					# Adds a class for this user's $tombstone
    			Write-Host "Tombstoned class for:" $user.SamAccountName "in $cname";
    		}
    	}
    }
	
	# Also don't forget we have to recycle courses and handle folders that are done and not added back (TODO)
	$UserTombstoneClasses = $tombstones[$user.SamAccountName]
	Write-Host "Checking tombstoned classes"
    if ($UserTombstoneClasses -ne $null) {
        $UserTombstoneClasses_Clone = $UserTombstoneClasses.Clone()
        foreach ($UserTombstoneClass in $UserTombstoneClasses_Clone.GetEnumerator()) {				# lets check the tombstoned classes to see if anything is older than a week
    		$diff = (Get-Date) - $UserTombstoneClass.Value							# get the time difference
    		if ($diff.TotalDays -gt $tombstone_days) {				    # if the difference is greater than the number of days
                $class_object = FormatClass $UserTombstoneClass.Key
    			$server_path = $Servers[$Majors[$class_object.Major]]
     			join-path $server_path -ChildPath $UserTombstoneClass.Key | join-path -ChildPath $user.SamAccountName | Remove-Item -Force # we fully delete the folder as its obvious noone is coming back
    			Write-Host "Removed tombstoned class for user:" $user.SamAccountName "in class" $UserTombstoneClass.Key
                
                # Remove from tombstones
                $UserTombstoneClasses.Remove($UserTombstoneClass.Key)
    		}
    	}
        
        if ($UserTombstoneClasses.Count -eq 0) { $tombstones.Remove($user.SamAccountName) }
    }
}

Write-Host "Parsed File and Created Users: Time Elapsed" ((Get-Date) - $start).TotalSeconds
Write-Host "Creating Classes and Adding Users"
foreach ($class_entry in $classes.GetEnumerator()) {
    $class = $class_entry.Value;
	$department = $Majors[$class.Major]
    $cname = $class.FormattedName
	$classad = Get-ADGroup -Filter { name -eq $cname } -SearchBase "OU=Classes,OU=$department,$LDAP"
	if ($classad -eq $null) 
	{ 
		$classad = CreateClass $class 
		Write-Host "Creating Class:" $class.Name
	}

	# Add users to class
	Write-Host "Adding Users to Class:" $class.Name
    if ($class_users[$class.FormattedName].Count -gt 0) {
    	foreach ($username in $class_users[$class.FormattedName]) {
    		# Get AD User and add to group
    		$userad = Get-ADUser -Filter { name -eq $username }	                # Gets the AD User (no search-base because this class may not be in  the users major)
    		Add-ADGroupMember $classad -members $userad -WhatIf:$compare		# Adds the user to the class group
    		
    		# Check If Tombstoned 
    		$userpath = join-path $Servers[$department] $class.FormattedName | join-path -ChildPath $username
    		if ($tombstones.ContainsKey($username) -and $tombstones[$username].ContainsKey($class.FormattedName)) {
    			# Unhide the folder 
    			$dir = Get-Item $userpath -Force  #Force makes it pick up the hidden folder
    			$dir.Attributes = $dir.Attributes -band ![System.IO.FileAttributes]"hidden"
    			
                # Update Tombstone Record
                $tombstones[$username].Remove($class.FormattedName)
                if ($tombstones[$username].Count -eq 0) { $tombstones.Remove($username) }
    			
                # Update user
    			Write-Host "Found Tombstoned Class and User: $username in" $class.FormattedName
    		}
    		elseif (!(Test-Path $userpath)) { # we check to ensure the directory doesn't already exist (perhaps it was moved by MoveSection
    			# Create User Directory
    			New-Item $userpath -type directory -WhatIf:$compare | out-null
    			Write-Host "Creating User Directory For Class: $username in" $class.FormattedName
    		}

    		# Add the user ACL
    		$acl = Get-ACL $userpath
    		$rule = CreateAccessRule $username "FullControl" $true "Allow"
    		$acl.SetAccessRule($rule)
    		Set-Acl $acl -Path $userpath -WhatIf:$compare
    		Write-Host "Settign User Folder ACL: $username in" $class.FormattedName
    	}
    }
}
Write-Host "Classes Completed in" ((Get-Date) - $start).TotalSeconds "Seconds"

# Export our tombstones
# This requires some modification so that it can be stored in the correct format
$csv = @()
if ($tombstones.Count -gt 0)
{
    Export-Clixml $tombstone_file -InputObject $tombstones
}
elseif (Test-Path $tombstone_file) 
{
    rm $tombstone_file
}

# Inheritance Fix
if ($do_inheritance) {
    Write-Host "Doing Inheritance Fix On TLDs"
    foreach ($server_entry in $Servers.GetEnumerator()) {
        $server = $server_entry.Value;
        if ($server -eq $null) { continue }

    	$acl = Get-ACL $server
        $acl.SetAccessRuleProtection($true,$false)
        
        $dom_user = CreateAccessRule "Domain Users" ("Read","Traverse","ListDirectory") $false "Allow"
        $dom_admin = CreateAccessRule "Domain Admins" "FullControl" $true "Allow"
        $system = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true
        $acl.AddAccessRule($dom_user)
        $acl.AddAccessRule($dom_admin)
        $acl.AddAccessRule($system)
        Set-ACL $acl -Path $server -WhatIf:$compare
        
    	if ($vebrose -eq $true) { Write-Host "Inheritance Broken On: $server" }
    }
}
Write-Host "Script Done"

<#
----------------------
New Version 2.0
----------------------
- Features
-- Variable Password											- fin`
-- Create Disabled or Locked Option								- fin`
-- Change Servers To Run Against								- fin`
-- Shares Settable 												- fin`
-- Auto-Expiration Date, Office									- fin` (Is office department?)
-- Comparison													- more or less fin`
-- Week Delete Time												- fin`
-- Move Sections												- fin`
-- New Classes, Dropped Classes, hide folders, remove acls		- fin`
-- Mark Folders as Pending Deletion								- fin`
#>