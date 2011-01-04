<#
    Network-Script
    This script builds the CADC Network
    Written by Alex Lusco
    http://www.github.com/luscoma/NetworkBuilder (private repo)
#>

<#
    These properties control the execution of the script
    Each is explained in detail as to what it controls
#>
$OITFile = "users.txt"                                                  # This is the OIT file to parse
                                                                        # It should be either absolute or relative to where the script is located                                                                       
$password = "tigers234AD" | ConvertTo-SecureString -AsPlainText -Force  # The default password used for each created user, it must conform to the domain password policy
                                                                        # or the creation of AD users will fail.  In addition it is converted to secure string because the AD
                                                                        # commands require it
$expiration = "5/20/2011"                                               # Expiration Date of the created users
$TombstoneFile = "tombstone.xml"                                        # The file used to store the currently tombstoned class folders and the date they were tombstoned
$tombstone_days = 7                                                     # This is the number of days a user's class folder is kept before it is permanately delated
                                                                        # Once this day length is reached, the user folder is deleted and unrecoverable if the 
                                                                        # student rejoins the class
$do_inheritance = $true                                                 # Enables or disables the inhertance fix for top-level folders
$compare = $false                                                       # Enables compare mode which does not cause any changes
                                                                        # NOTE: This will fail currently (I believe) due to Get-Acl and Set-ACL being attempted on a non-existant folder, this will be tested in the future
$Vebrose = $false                                                       # Enables the vebrose mode of logging


<#
    This is a list of variables which are used to lookup server paths and acceptable class majors
    As well as domain ldap information.  If this information is incorrect except incorrect results
#>
<#
    List of Majors
    This is used to look up majors and correspond them to an appropriate department.  Each key in this
    lookup table must have a value which corresponds to a key in the $ClassFolders lookup table
#>
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

<#
    Class Folder Paths
    This lookup table holds each departments top-level class folder.
    Each class in that department will be created under this folder.
#>
$ClassFolders = @{
    "ARCH" = "\\localhost\SHARE\ARCH_Classes";
    "BSCI" = "\\localhost\SHARE\BSCI_Classes";
    "INDD" = "\\localhost\SHARE\INDD_Classes";
    "CADC" = "\\localhost\SHARE\CADC_Classes";
};
<#
    LDAP Suffixes and Domain Prefixes
    This is used when accessing the AD so that users are found and added appropriately
#>
$LDAP       = "DC=test,DC=local";                                     # The LDAP suffix for the domain in LDAP Format, i.e. For domain.local it would be DC=domain,DC=local
$DOMAIN     = "TEST\"                                               # The Domain Prefix for users, i.e. MYDOMAIN\
$FullDomain = "test.local"                                      # Full suffix of domain, i.e. domain.local

<#
    This is a group of helper functions which are used 
    by the script to perform common operations
#>
<#
    CreateClass

    Creates folders and AD entries, currently it assumes the class does not exist and will not double check 
    when executing.  The user should check before calling

    $class      FormatClass Object
#>
function CreateClass($class)
{
    # Get LDAP Paths and Users
    $LDAP_OU = "OU={0},{1}" -f $class.Department,$LDAP
    $FacultyGroupName = "{0} Faculty" -f $class.Department                                                                             # Sets the Faculty group which is Department Faculty
    $FacultyAD = Get-ADGroup -Filter { name -eq $FacultyGroupName } -SearchBase "OU=Groups,$LDAP_OU"                                   # Finds the group in the AD
    
    # Creates a new class, its folders and groups
    $ClassAD = New-ADGroup $class.FormattedName -Path "OU=Classes,$LDAP_OU" -GroupScope "global" -WhatIf:$compare -PassThru            # Create the class group
    $InstructorAD = New-ADGroup $class.Faculty -Path "OU=Instructors,$LDAP_OU" -GroupScope "global" -WhatIf:$compare -PassThru         # Create the faculty group
    
    # Add initial groups
    Add-ADGroupMember $FacultyGroup -members $InstructorAD -WhatIf:$compare                                                            # Adds the faculty group to the class instructor group
    Add-ADGroupMember $ClassAD -members $InstructorAD -WhatIf:$compare                                                                 # Adds the instructor group to the class group
    
    # Create Folders on the server
    $Class_Path = join-path $ClassFolders[$department] -ChildPath $class.FormattedName                                                 # Makes the path for the class
    $Assign_Path = join-path $Class_Path -ChildPath "ASSIGN"                                                                           # Makes the assign folder path
    $Shared_Path = join-path $Class_Path -ChildPath "SHARED"                                                                           # Makes the shared folder path
    New-Item $Class_Path -type directory -WhatIf:$compare | out-null                                                                   # Create the main class folder
    New-Item $Assign_Path -type directory -WhatIf:$compare | out-null                                                                  # Create assignment folder
    New-Item $Shared_Path -type directory -WhatIf:$compare | out-null                                                                  # Create shared folder
                                                                                                                                       # These our piped to null so they don't echo OK to the console (which you can't turn off...)

    # Set ACLS For Main Path
    $acl = Get-Acl $Class_Path                                                                                                         # Retrieves the ACLs on the class folder
    $UTM_acl = CreateAccessRule $class.UTM "FullControl" $true "Allow"                                                                 # Adds the UTM user as full control and for inheritance
    $SYS_acl = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true                                                             # Adds the SYSTEM as full control and for inheritance
    $Class_acl = CreateAccessRule $class.FormattedName "ReadAndExecute" $false "Allow"                                                 # Sets the class group for Read And Execute but no inheritance
    $Faculty_acl = CreateAccessRule $class.Faculty "FullControl" $true "Allow"                                                         # Sets the instructor group for Full Control and inheritance
    $acl.AddAccessRule($UTM_acl)                                                                                                       # Add the rules
    $acl.AddAccessRule($SYS_acl)
    $acl.AddAccessRule($Class_acl)
    $acl.AddAccessRule($Faculty_acl
    Set-Acl $acl -Path $Class_Path -WhatIf:$compare                                                                                    # Set the ACLs on the path
    
    # Adjust ACL for assign folder
    $acl = Get-Acl $Assign_Path                                                                                                        # Retrieves the ACLs on the assign folder
    $Class_Assign_acl = CreateAccessRule $class.FormattedName "ReadAndExecute" $true "Allow"                                           # Gives the class group read and execute priveledges and inheritance
    $acl.AddAccessRule($Class_Assign_acl)                                                                                              # Add the rule
    Set-Acl $acl -Path $Assign_Path -WhatIf:$compare                                                                                   # Set the ACLS
    
    # Adjust ACL for shared folder
    $acl = Get-Acl $Shared_Path                                                                                                        # Gets the ACLs for the shared folder
    $Class_Full_acl = CreateAccessRule $class.FormattedName "FullControl" $true "Allow"                                                # Adds the class group for full control and inheritance
    $acl.AddAccessRule($Class_Full_acl)                                                                                                # Add the rule
    Set-Acl $acl -Path $Shared_Path -WhatIf:$compare                                                                                   # Set the ACLS
    
    $classgroup                                                                                                                        # Return the class-group from AD
}
<#
    CreateAccessRule
    Creates an access rule a bit easier than the necessary list format
    
    $user       The username to create the rule for
    $perm       Permission to extend to the user
    $inherit    True/False to enable/disable inheritance
    $type       "Allow" or "Deny"
    $nodomain   Defaults to false, true to not automatically append the domain
#>  
function CreateAccessRule($user, $perm, $inherit, $type, $nodomain = $false) 
{
    # Build the inheritance and propagation flags
    $inheritance_flags = [System.Security.AccessControl.InheritanceFlags]"None"                                                        # Default inheritance to none
    $propagation_flags = [System.Security.AccessControl.PropagationFlags]"NoPropagateInherit"                                          # Default to not propagate
    if ($inherit) {                                                                                                                    # if $inherit = true {
        $inheritance_flags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit","ObjectInherit"                        # Set folders and items to inherit
        $propagation_flags = [System.Security.AccessControl.PropagationFlags]"None"                                                    # Do not set propagation (strangely forces the expected behavior here)
    }
    
    # Create Permission and returns it
    $u = "{0}@{1}" -f $user,$FullDomain                                                                                                # Make user in format of user@domain
    if ($nodomain) { $u = $user }                                                                                                      # If needed set user to not include domain
    New-Object System.Security.AccessControl.FileSystemAccessRule $u,$perm,$inheritance_flags, $propagation_flags, $type               # Creates the file system access rule
}
<#
    MoveUserClassSection
    
    Moves a user from one section to another section
    This function takes into account the possibility that a class is not yet created and performs the necessary steps to create it and add the user to it.
    It does not drop the user from the old class in AD
    
    $user               Username
    $Dropped_Class      Class object representing the class dropped
    $Add_Class          Class object representing the class added
#>
function MoveUserClassSection($user, $Dropped_Class, $Add_Class)
{
    # Add User to New Group
    $AddClass_Department = $Add_Class.Department                                                                                      # Gets the classes department
    $ClassAd = Get-ADGroup -Filter { name -eq $Add_Class.FormattedName } -SearchBase "OU=Classes,OU=$AddClass_Department,$LDAP"       # Gets the new class to be added
    if ($ClassAd -eq $null) { $ClassAd = CreateClass($Add_Class); }                                                                   # Creates the class if it doesn't exist yet

    # Move User Folder
    $department = $Majors[$Dropped_Class.Major]                                                                                       # Gets the department of the dropped class
    $Drop_Path = join-path $ClassFolders[$Dropped_Class.Department] -ChildPath $Dropped_Class.FormattedName |                         # Gets dropped classes user folder
                            join-path -ChildPath $user.SamAccountName
    $Add_Path = join-path $ClassFolders[$Dropped_Class.Department] -ChildPath $Add_Class.FormattedName                                # Gets the added classes folder (not the user directly)
    Move-Item $Drop_Path -Destination $Add_Path -WhatIf:$compare                                                                      # Moves the user folder to the added class folder
}
<#
    FormatClass
    Takes a class name and converts it to a class object
    This includes the name, FormattedName, Major, and Department Fields
    
    $Class_Name     Name of Class
    
    Returns: Class Object
#>
function FormatClass($Class_Name)
{
    $Name = $Class_Name.Replace("_","")                                                                         # Strip any underscores in case this is a formatted name
    #Returns a class object from the name
    @{                                                                                                          # New Hash Table
        Name = $Name ;                                                                                          # Name = the unformatted name
        FormattedName = ("{0}_{1}_{2}" -f $Name.Substring(0,4),$Name.Substring(4,4),$Name.Substring(8,3));      # Formatted Name = The MAJOR_CLASS_SECTION
        Major = $Name.Substring(0,4) ;                                                                          # The Major
        Department = $Majors[$Name.Substring(0,4)] ;                                                            # The Department
        UTM = "{0}_UTM" -f $Majors[$Name.Substring(0,4)] ;                                                      # UTM User
        Faculty = "{0}_{1}_{2}_FAC" -f $Name.Substring(0,4),$Name.Substring(4,4),$Name.Substring(8,3) ;         # Faculty Group for Class
    }
}
# Traps Any Errors
trap { 
    Write-Host "Error Occurred: $_"; 
    Write-Host "Terminating Execution";
    
    if ($compare -eq $false) { break; }     # In non-compare mode if a serious error occurres we dump
    else { continue; }                      # if we're in comparison mode the Get-ACL will fail if the folder doesn't exist so we just truck through it
}

<# 
    This is the Actual Script
    From here on out this is the meat and potatoes
#>
# Load tombstone files
$Tombstones = @{}                                      # This is the tombstones hash table
if (Test-Path $TombstoneFile) {                        # Does the tombstone file exist?
    $Tombstones = Import-Clixml $TombstoneFile         # If so deserialize the XML
}

# This imports the csv file of users into a ready to use format
# Most of this is easy, the classes become inconvient but we fix that in a bit
Write-Host "Importing OIT User File"
$users = Import-Csv $OITFile -Header  "Givenname","MiddleName","Surname","SamAccountName","Year","Major",
                                   "Password","Class1","Class2","Class3","Class4","Class5","Class6",
                                   "Class7","Class8","Class9","Class10" -Delimiter ';' |                        # Import the file with the given headers as properties
         where { $Majors.ContainsKey($_.Major) } |                                                              # Only include users which are in one of our Majors     
         add-member -membertype "ScriptProperty" -name Department -Value { $Majors[$this.Major] } -PassThru     # Add a department field to these students based on their major

# We collapse down the csv file into user and class objects and perform the necessary operations
$classes = @{}                                                                                                  # Holds a global list of classes
$Class_Users = @{}                                                                                              # Holds a list of all classes and the users which are in them
$Start = Get-Date                                                                                               # Used to time how long it takes
Write-Host "Start" (Get-Date)
foreach ($user in $users) {                                                                                     # For every user
    $LDAP_OU = "OU={0},{1}" -f $user.Department,$LDAP
    $UserAD = Get-ADUser -Filter { Name -eq $user.SamAccountName } -SearchBase "OU=Students,$LDAP_OU"           # Attempt to retreive the user from the ad
    if ($UserAD -eq $null)                                                                                      # If the user doesn't exist
    {
        $UserAD = New-ADUser $user.SamAccountName -SamAccountName $user.SamAccountName `                        # Create the AD Object with the given properties
                                    -GivenName $user.GivenName -Surname $user.Surname  `
                                    -AccountPassword $password -Enabled $false -ScriptPath 'SCRIPTLOGIC' `
                                    -AccountExpirationDate $expiration -Path "OU=Students,$LDAP_OU" `
                                    -WhatIf:$compare -PassThru
        Write-Host "Creating a new user: " $user.SamAccountName
    }
        
    # Loop through users classes and add unique ones to our big list
    # We do some shady stuff and retreive all of the properties labeled Class* then load them into an array of classes
    $MyClasses = $user | get-member -Name "Class*" | select -ExpandProperty Definition |                    # Get all the properties in the format of Class*
                    foreach { $_.Substring($_.IndexOf("=")+1) } |                                           # Get anything After the = sign (they are in the format Class#=ClassName)
                    where { $_.Length -gt 1 -and $Majors.ContainsKey($_.Substring(0,4)) } |                 # Get any which have a length > 1 (aka existed) and are in our major
                    foreach { FormatClass $_ }                                                              # Return a class object for each of the classes 
    if ($MyClasses -ne $null) {                                                                             # Does this user have any classes?
        foreach ($Class in $MyClasses) {                                                                    # if so lets loop through them
            if (!$classes.ContainsKey($Class.FormattedName))  {                                             # Have we seen this class before?
                $classes.Add($Class.FormattedName, $Class);                                                 # Add this class to our class list                              
                $Empty_Array = New-Object System.Collections.ArrayList                                      # Create an empty array (the long way)
                $Class_Users.Add($Class.FormattedName,$Empty_Array);                                        # Add the class name and empty list to our Class_Users object
                
                if ($Vebrose) { Write-Host "Found New Class: " $Class.Name }                                # Tell you about it if vebrose mode is on
            }
        }
    }
    
    # Get a list of our classes but only the formatted names
    $Class_Names = $MyClasses | foreach { $_.FormattedName }
    
    # Get Groups and handle dropped classes
    $GroupsAD = Get-ADPrincipalGroupMembership $UserAD                                                      # Retrieves the user's groups
    $Group_Names = $GroupsAD | select name -ExpandProperty name                                             # Retreives the names of all groups this user is a member of
    
    # Store list of classes user should add (aka those which were enrolled but are not currently a member)
    $AddedClasses = $Class_Names | where { $Group_Names -notcontains $_  }                                  # Get the groups that we aren't currently in and need to be added to
    if ($AddedClasses -ne $null) {                                                                          # Were there any we need to be added to?    
        foreach ($Add in $AddedClasses) {                                                                   # Lets loop through them
            $Class_Users[$Add].Add($user.SamAccountName) | out-null                                         # Add the user to this class in the list of classes and users
            if ($Vebrose) { Write-Host "Adding Class: $add for" $user.SamAccountName }                      # Tell you about it if vebrose is on
        }
    }
    
    # Drop the classes that should be dropped (aka those which were a member but are no longer enrolled)
    $DroppedClasses = $GroupsAD | 
                        where { $_.name -match "\w{4}_\d{4}_\d{3}" -and $Class_Names -notcontains $_.name } # Filter the groups by the names that don't exist anymore in our class names list
    if ($DroppedClasses -ne $null) {                                                                        # Should any classes be dropped?
        foreach ($Drop in $DroppedClasses) {                                                                # If so lets do so
            $DropAD = Get-ADGroup -Filter { name -eq $Drop.name } -SearchBase "OU=Classes,$LDAP_OU"         # Retreives the AD Group for this class
            Remove-ADPrincipalGroupMembership $UserAD -memberOf $DropAD -WhatIf:$compare -Confirm:$false    # Removes the AD user from the group
            if ($Vebrose) { Write-Host "Dropping Class:" $Drop.name "for" $user.SamAccountName }            # If vebrose tell you this guy is dropped
            
            # Check if section was moved and not a full drop
            $New_Section = $AddedClasses | where { $_ -match ($Drop.name.Substring(0,8)+"*") }              # if any section matches the prefix sans the section number 
                                         | select -First 1                                                  # (only select 1, hopefully they dont join two sections, if so we can't help them)

            if ($New_Section -ne $null) {                                                                   # Did they move to a new section?
                MoveUserClassSection $user (FormatClass $Drop.name) $classes[$New_Section]                  # If so lets move them
                if ($Vebrose) { Write-Host "Moved User Section from" $Drop.name "to" $New_Section }         # If vebrose tell youa bout it
            }
            else {                                                                                          # If its not a section move we must tombstone the class
                # Remove the ACL
                $UserPath = join-path $ClassFolders[$Drop.Department] -ChildPath `                          # Get the path for this user's class folder
                                            ("{0}\{1}" -f $Drop.Name,$user.SamAccountName)
                $acl = Get-ACL $UserPath                                                                    # Get the acls for that folder
                $rule = $acl.Access | where { $_.IdentityReference -eq ("$DOMAIN"+$user.SamAccountName) }   # Get the rule which gives the user access
                if ($rule -ne $null) { $acl.RemoveAccessRule($rule) }                                       # If the rule exists remove it
                Set-Acl $acl -Path $UserPath -WhatIf:$compare                                               # Set the acls
                
                # Hide the folder
                $UserDir = Get-Item $UserPath                                                               # Get the users folder
                $UserDir.Attributes = $UserDir.Attributes -bor [System.IO.FileAttributes]"hidden"           # Or in the hidden attribute

                # Tombstone Folder
                if ($Tombstones.Containskey($user.SamAccountName)) {                                        # If the user does not have any other tombstoned folders        
                    $Tombstones.Add($user.SamAccountName,@{});                                              # We creates a tombstone for this user
                }
                
                # Add a tombstone entry
                $Tombstones[$user.SamAccountName].Add($Drop.Name, (Get-Date))                                   # Add the class name to this users tombstoned list and the current date
                if ($Vebrose) { Write-Host "Tombstoned class for:" $user.SamAccountName "in" $Drop.Name; }      # If vebrose tell you about it
            }
        }
    }

    # Also don't forget we have to recycle courses and handle folders that are done and not added back 
    $UserTombstoneClasses = $Tombstones[$user.SamAccountName]                                               # Get the users list of tombstoned classes      
    if ($Vebrose) { Write-Host "Checking tombstoned classes for:" $user.SamAccountName }                    # If veborse tell you about it
    if ($UserTombstoneClasses -ne $null) {                                                                  # Does the user have any tombstoned classes
        $UserTombstoneClasses_Clone = $UserTombstoneClasses.Clone()                                         # If so lets clone the list so we can iterate over it while removing items from the original
        foreach ($TombstoneClass in $UserTombstoneClasses_Clone.GetEnumerator()) {                          # Iterate over the cloned list  
            $diff = (Get-Date) - $TombstoneClass.Value                                                      # get the time difference from when the class was tombstoned until now
            if ($diff.TotalDays -gt $tombstone_days) {                                                      # If the difference is greater than the number of days required
                $ClassObject = FormatClass $TombstoneClass.Key                                              # Create a class object for this tombstoned class
                join-path $ClassFolders[$ClassObject.Department] -ChildPath $TombstoneClass.Key |           # We get the path to the users folder
                        join-path -ChildPath $user.SamAccountName | 
                        Remove-Item -Force                                                                  # And remove the item (-Force is required becaues it is a hidden folder)

                if ($Vebrose) { Write-Host "Removed tombstoned class for user:" $user.SamAccountName "in class" $TombstoneClass.Key } # tell you about it

                # Remove from tombstones list
                $UserTombstoneClasses.Remove($TombstoneClass.Key)                                       # Remove this class from the original (non-cloned) list
            }
        }

        if ($UserTombstoneClasses.Count -eq 0) { $Tombstones.Remove($user.SamAccountName) }                 # if user has no more tombstones remove the user from the tombstoned list
    }
}

# Now we focus on creating the classes and added the users to those classes
Write-Host "Parsed File and Created Users: Time Elapsed" ((Get-Date) - $Start).TotalSeconds                 # tell you how long it took to do part 1
Write-Host "Creating Classes and Adding Users"                                                              # Say what were doing
foreach ($class_entry in $classes.GetEnumerator()) {                                                        # Enumerate over every class we have    
    $class = $class_entry.Value;                                                                            # Get The class object
    $department = $Majors[$class.Major]                                                                     # Get the department
    $cname = $class.FormattedName                                                                           # Get the formatted name
    $classad = Get-ADGroup -Filter { name -eq $cname } -SearchBase "OU=Classes,OU=$department,$LDAP"        # Retreive the AD Group for the class
    if ($classad -eq $null)                                                                                 # If the class does not already exist       
    { 
        $classad = CreateClass $class                                                                       # Lets create it
        if ($Vebrose) { Write-Host "Creating Class:" $class.Name }                                          # Tell you we're creating a class if in vebrose mode
    }

    # Add users to class
    if ($Vebrose) { Write-Host "Adding Users to Class:" $class.Name }                                       # lets add the necessary users to this class
    if ($Class_Users[$class.FormattedName].Count -gt 0) {                                                   # If this class has any users to be added to it
        foreach ($username in $Class_Users[$class.FormattedName]) {                                         # Lets loop through the users
            # Get AD User and add to group
            $userad = Get-ADUser -Filter { name -eq $username }                                             # Gets the AD User (no search-base because this class may not be in  the users major)
            Add-ADGroupMember $classad -members $userad -WhatIf:$compare                                    # Adds the user to the class group
            
            # Check If Tombstoned 
            $userpath = join-path $ClassFolders[$department] $class.FormattedName |                              # Get the users path
                        join-path -ChildPath $username  
            if ($Tombstones.ContainsKey($username) -and 
                        $Tombstones[$username].ContainsKey($class.FormattedName)) {                         # Check if the class is tombstoned for the user
                # Unhide the folder                                                                         # If it is lets unhide it and just add the ACL back
                $dir = Get-Item $userpath -Force                                                            # Force makes it pick up the hidden folder
                $dir.Attributes = $dir.Attributes -band ![System.IO.FileAttributes]"hidden"                 # Remove the hidden attribute
                
                # Update Tombstone Record
                $Tombstones[$username].Remove($class.FormattedName)                                         # Remove this class from the tombstoned list            
                if ($Tombstones[$username].Count -eq 0) { $Tombstones.Remove($username) }                   # If the user has no other tombstoned classes remove the user from the tombstoned list
                
                # Update user
                if ($Vebrose) { Write-Host "Found Tombstoned Class and User: $username in" $class.FormattedName }       # Tell someone about it
            }
            elseif (!(Test-Path $userpath)) {                                                               # we check to ensure the directory doesn't already exist (perhaps it was moved by MoveClassSection)
                # Create User Directory
                New-Item $userpath -type directory -WhatIf:$compare | out-null                              # Create the users directory
                if ($Vebrose) { Write-Host "Creating User Directory For Class: $username in" $class.FormattedName }     # Tell someone about it
            }

            # Add the user ACL
            $acl = Get-ACL $userpath                                                                        # Get the ACLS on the user directory
            $rule = CreateAccessRule $username "FullControl" $true "Allow"                                  # Create a rule for full control by the user
            $acl.AddAccessRule($rule)                                                                       # Add it
            Set-Acl $acl -Path $userpath -WhatIf:$compare                                                   # Set-Acls to the directory
            if ($Vebrose) { Write-Host "Setting User Folder ACL: $username in" $class.FormattedName }       # Tell someonea bout it
        }
    }
}
Write-Host "Classes Completed in" ((Get-Date) - $Start).TotalSeconds "Seconds"                              # How long did it takes us?

# Export our tombstones
if ($Tombstones.Count -gt 0) { Export-Clixml $TombstoneFile -InputObject $Tombstones }                     # Do we still have any tombstoned classes, if so serialize the hash table of items
elseif (Test-Path $TombstoneFile) { rm $TombstoneFile }                                                   # If not remove the tombstone file

# Inheritance Fix
if ($do_inheritance) {                                                                                      # Should we do the inheritance fixes?
    Write-Host "Doing Inheritance Fix On Top Level Folders"
    foreach ($server_entry in $ClassFolders.GetEnumerator()) {                                                   # Loop through our top-level folders
        $server = $server_entry.Value;                                                                                                                          
        if ($server -eq $null) { continue }                                                                 # If for some reason that value doesn't exist lets skip it

        # Get ACLS
        $acl = Get-ACL $server                                                                              # Get the top levfel path acls
        $acl.SetAccessRuleProtection($true,$false)                                                          # Basically ignore any inherited ACLS
        
        $dom_user = CreateAccessRule "Domain Users" ("Read","Traverse","ListDirectory") $false "Allow"      # Add a permission for domain users which is not inherited
        $dom_admin = CreateAccessRule "Domain Admins" "FullControl" $true "Allow"                           # Add a permission for domain admins which gives full control and is inherited
        $system = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true                               # Create a SYSTEM permission with full control
        $acl.AddAccessRule($dom_user)
        $acl.AddAccessRule($dom_admin)
        $acl.AddAccessRule($system)
        Set-ACL $acl -Path $server -WhatIf:$compare                                                         # Set the ACLS on the path
        
        if ($Vebrose) { Write-Host "Inheritance Broken On: $server" }
    }
}
Write-Host "Script Done Completed in " ((Get-Date) - $Start).TotalSeconds "Seconds" 
