<#
    Network-Script
    This script builds the CADC Network
    Written by Alex Lusco
    http://www.github.com/luscoma/NetworkBuilder

    To Run A Unsigned Script
    Set-ExecutionPolicy Unrestricted
#>

<#
    These properties control the execution of the script
    Each is explained in detail as to what it controls
    They can be passed when calling via the command line
#>
param(
        [string]$OITFile                = "users.txt",                  # This is the OIT file to parse
                                                                        # It should be either absolute or relative to where the script is located
        [string]$UserPasswordString     = "tigers",                     # The default password used for each created user, it must conform to the domain password policy
        [DateTime]$UserExpireDate       = "5/20/2011",                  # Expiration Date of the created users
        [string]$TombstoneFile          = "tombstone.xml",              # The file used to store the currently tombstoned class folders and the date they were tombstoned
        [int]$TombstoneDays             = 7,                            # This is the number of days a user's class folder is kept before it is permanately delated
                                                                        # Once this day length is reached, the user folder is deleted and unrecoverable if the student rejoins the class
        [string]$FullDomain             = "test.local",                 # The full domain suffix, this is parsed for the LDAP suffix and the domain prefix
        [string]$AdminEmail             = "davis51@auburn.edu",         # The Email to email the log file to upon completion
        [string]$EmailServer            = "tigerout.auburn.edu",        # The SMTP server to send the e-mail

        [Switch]$DoInheritance          = $false,                       # Enables or disables the inhertance fix for top-level folders
        [Switch]$Compare                = $false,                       # Enables compare mode which does not cause any changes
        [Switch]$Vebrose                = $false,                       # Enables the vebrose mode of logging
        [Switch]$EnableStats            = $true,                        # Prints some stats at the end of the script of what was or would be cahnged
        [Switch]$NoLogging              = $false,                       # Disables e-mailing of the log file
        [Switch]$NoEmail                = $false                        # Disables e-mailing of the log file
     )

# Enable logging unless told not to
if ($NoLogging -eq $false) { start-transcript -Path ("./builder-{0}.log" -f (get-date -uformat "%m-%d-%Y")) }

# Ensure the AD Module is imported
import-module activedirectory

<#
    LDAP Suffixes and Domain Prefixes
    This is used when accessing the AD so that users are found and added appropriately
#>
$DOMAIN = "{0}\" -f $FullDomain.Substring(0,$FullDomain.IndexOf(".")) # The Domain Prefix for users which is retreived by substring the first part of the $FullDomain, i.e. MYDOMAIN\ from mydomain.net
$LDAP = [String]::Join(',', ($FullDomain.Split('.') | % { "DC=$_" }))   # The LDAP suffix for the domain in LDAP Format, i.e. For domain.local it would be DC=domain,DC=local


# Convert the password to the secure string
$UserPassword = $UserPasswordString |                                   # We convert the given password to a secure string
                    ConvertTo-SecureString -AsPlainText -Force          # since the AD commands require it... which is dumb

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
    "PARC" = "ARCH";
    "ARCH" = "ARCH";
    "ARIA" = "ARCH";
    "PLND" = "ARCH";
    "LAND" = "ARCH";
    "CPLN" = "ARCH";

    # Building Science
    "BSCI" = "BSCI";
    "PBSC" = "BSCI";
    "BSCC" = "BSCI";

    # Industrial Design
    "INDD" = "INDD";
    "GDES" = "INDD";
    "PGDE" = "INDD";
    "PIND" = "INDD";
    "PATG" = "INDD";
    "ENVD" = "INDD";

    # Design Build
    "DBLD" = "DBLD";

    # College of Architecture, Design, and Construction
    "CADC" = "CADC";
};

<#
    Class Folder Paths
    This lookup table holds each departments top-level class folder.
    Each class in that department will be created under this folder.
#>
$ClassFolders = @{
    "ARCH" = "\\cadc12\ARCH_Classes";
    "BSCI" = "\\cadc13\BSCI_Classes";
    "INDD" = "\\cadc14\INDD_Classes";
    "DBLD" = "\\cadc15\DBLD_Classes";
    "CADC" = "\\cadc16\CADC\CADC_Classes";
};

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
    $LDAP_OU = "OU={0},{1}" -f $class.Department,$LDAP                                                                                 # Make the LDAP Suffix once
    $FacultyGroupName = $class.Faculty                                                                                                 # This is done due to the AD Filter Syntax... fail

    $FacultyAD = Get-ADGroup -Filter { name -eq $FacultyGroupName } -SearchBase "OU=Groups,$LDAP_OU"                                   # Finds the group in the AD

    # Creates a new class, its folders and groups
    $ClassAD = New-ADGroup $class.FormattedName -Path "OU=Classes,$LDAP_OU" -GroupScope "global" -WhatIf:$Compare -PassThru            # Create the class group
    $InstructorAD = New-ADGroup $class.Instructor -Path "OU=Instructors,$LDAP_OU" -GroupScope "global" -WhatIf:$Compare -PassThru      # Create the faculty group

    # Add initial groups
    if (!$Compare) {
        if ($Vebrose) { Write-Host "AD Groups" $FacultyAD $InstructorAD }                                                              # The Debug output for the faculty ad and instructor ad group
        Add-ADGroupMember $FacultyAD -members $InstructorAD -WhatIf:$Compare                                                           # Adds the faculty group to the class instructor group
        Add-ADGroupMember $ClassAD -members $InstructorAD -WhatIf:$Compare                                                             # Adds the instructor group to the class group
    }

    # Create the class folders
    CreateClassFolders $class
    CheckSharedFolder $class
    $ClassAD                                                                                                                           # Return the class-group from AD
}
<#
    CreateClassFolders

    Creates the folders used for a class but does not attempt to create the AD group
    This is useful if for example the class group exists but the folders are deleted

    $class FormatClass object
#>
function CreateClassFolders($class)
{
    # Create Folders on the server
    $Class_Path = join-path $ClassFolders[$class.Department] -ChildPath $class.FormattedName                                           # Makes the path for the class
    if (Test-Path $Class_Path) { return }                                                                                              # Checks if the class folder already exists (if it does it assumes that it shouldn't recreate it)

    # Create the remaining paths and actually create the directories
    $Assign_Path = join-path $Class_Path -ChildPath "ASSIGN"                                                                           # Makes the assign folder path
    $Shared_Path = join-path $Class_Path -ChildPath "SHARED"                                                                           # Makes the shared folder path
    New-Item $Class_Path -type directory -WhatIf:$Compare | out-null                                                                   # Create the main class folder
    New-Item $Assign_Path -type directory -WhatIf:$Compare | out-null                                                                  # Create assignment folder
    New-Item $Shared_Path -type directory -WhatIf:$Compare | out-null                                                                  # Create shared folder
                                                                                                                                       # These our piped to null so they don't echo OK to the console (which you can't turn off...)
    # Check Compare Mode, the rest of this stuff will fail (the access rule stuff specifically)
    if ($Compare) { return }

    # Set ACLS For Main Path
    $acl = Get-Acl $Class_Path                                                                                                         # Retrieves the ACLs on the class folder
    $UTM_acl = CreateAccessRule $class.UTM "FullControl" $true "Allow"                                                                 # Adds the UTM user as full control and for inheritance
    $SYS_acl = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true                                                             # Adds the SYSTEM as full control and for inheritance
    $Class_acl = CreateAccessRule $class.FormattedName "ReadAndExecute" $false "Allow"                                                 # Sets the class group for Read And Execute but no inheritance
    $Faculty_acl = CreateAccessRule $class.Instructor "FullControl" $true "Allow"                                                         # Sets the instructor group for Full Control and inheritance
    $acl.AddAccessRule($UTM_acl)                                                                                                       # Add the rules
    $acl.AddAccessRule($SYS_acl)
    $acl.AddAccessRule($Class_acl)
    $acl.AddAccessRule($Faculty_acl)
    Set-Acl $acl -Path $Class_Path -WhatIf:$Compare                                                                                    # Set the ACLs on the path

    # Adjust ACL for assign folder
    $acl = Get-Acl $Assign_Path                                                                                                        # Retrieves the ACLs on the assign folder
    $Class_Assign_acl = CreateAccessRule $class.FormattedName "ReadAndExecute" $true "Allow"                                           # Gives the class group read and execute priveledges and inheritance
    $acl.AddAccessRule($Class_Assign_acl)                                                                                              # Add the rule
    Set-Acl $acl -Path $Assign_Path -WhatIf:$Compare                                                                                   # Set the ACLS

    # Adjust ACL for shared folder
    $acl = Get-Acl $Shared_Path                                                                                                        # Gets the ACLs for the shared folder
    $Class_Full_acl = CreateAccessRule $class.FormattedName "FullControl" $true "Allow"                                                # Adds the class group for full control and inheritance
    $acl.AddAccessRule($Class_Full_acl)                                                                                                # Add the rule
    Set-Acl $acl -Path $Shared_Path -WhatIf:$Compare                                                                                   # Set the ACLS
}

<#
    CheckSharedFolder
    Adds this class to a shared folder group if it doesn't exist
    Will also create the folder/group if it doesn't exist

    $class      The Class Object
#>
function CheckSharedFolder($class)
{
    # Check if the group exists in the AD and if our class is not in there add us to it
    $SharedName = $class.SharedName
    $LDAP_OU = "OU={0},{1}" -f $class.Department,$LDAP   
    $GroupAD = Get-ADGroup -Filter { name -eq $SharedName } -SearchBase "OU=Groups,$LDAP_OU"
    if ($GroupAD -eq $null) {
        $GroupAD = New-ADGroup $SharedName -Path "OU=Groups,$LDAP_OU" -GroupScope "global" -WhatIf:$Compare -PassThru
    }

    if ($Compare) { return }                                                                                # If compare kick out

    # Ensure this class is a member of the group
    $ClassName = $class.FormattedName
    $ClassAD = Get-ADGroup -Filter { name -eq $ClassName } -SearchBase "OU=Classes,$LDAP_OU"                # This should never be null since we called createclass first            
    Add-ADGroupMember $GroupAD -members $ClassAD -WhatIf:$Compare   

    # Check if the folder exists
    $Shared_Path = join-path $ClassFolders[$class.Department] -ChildPath $SharedName                        # Build the path for this folder
    if (!(test-path $Shared_Path) -and !$Compare)                                                           # If the folder doesn't exist add it
    {
        New-Item $Shared_Path -type directory -WhatIf:$Compare | out-null                                   # Create the folder       

        # Modify the ACL List
        $acl = Get-ACL $Shared_Path                                                                         # Get the ACL LIST
        $UTM_acl = CreateAccessRule $class.UTM "FullControl" $true "Allow"                                  # Adds the UTM user as full control and for inheritance
        $SYS_acl = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true                              # Adds the SYSTEM as full control and for inheritance
        $Shared_acl = CreateAccessRule $SharedName "Modify" $false "Allow"                                  # Sets the class group for Read And Execute but no inheritance
        $acl.AddAccessRule($UTM_acl)                                                                                                       # Add the rules
        $acl.AddAccessRule($SYS_acl)
        $acl.AddAccessRule($Shared_acl)
        Set-Acl $acl -Path $Shared_Path -WhatIf:$Compare 
    }
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
    $AddClass_FormattedName = $Add_Class.FormattedName                                                                                # Used due to the filter syntax not allowing hash table access
    $ClassAd = Get-ADGroup -Filter { name -eq $AddClass_FormattedName } -SearchBase "OU=Classes,OU=$AddClass_Department,$LDAP"       # Gets the new class to be added
    if ($ClassAd -eq $null) { $ClassAd = CreateClass($Add_Class); }                                                                   # Creates the class if it doesn't exist yet

    # Move User Folder
    $department = $Majors[$Dropped_Class.Major]                                                                                       # Gets the department of the dropped class
    $Drop_Path = join-path $ClassFolders[$Dropped_Class.Department] -ChildPath $Dropped_Class.FormattedName |                         # Gets dropped classes user folder
                            join-path -ChildPath $user.SamAccountName
    $Add_Path = join-path $ClassFolders[$Dropped_Class.Department] -ChildPath $Add_Class.FormattedName                                # Gets the added classes folder (not the user directly)
    if (!(Test-Path $Drop_Path)) { return }
    Move-Item $Drop_Path -Destination $Add_Path -WhatIf:$Compare                                                                      # Moves the user folder to the added class folder
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
    if ($Class_Name.length -ne 11) {
        # We return nothing, this will be a null entry
        Write-Error -Message ("Invalid Class Name, Failed To Format {0}, it will be skipped." -f $Class_Name) -Category InvalidData
        return
    }

    $name = $Class_Name.Replace("_","");                                                                        # Strips a formatted name if given
    switch($name[4])
    {
        '1' {$year = "1st"}
        '2' {$year = "2nd"}
        '3' {$year = "3rd"}
        default { $year = ("{0}th" -f $name[4]) }
    }
    @{                                                                                                          # Creates a new hash table
        Name = $name ;                                                                                          # Stores the unformatted name
        FormattedName = "{0}_{1}_{2}" -f $name.Substring(0,4),$name.Substring(4,4),$name.Substring(8,3) ;       # Stores the formatted name
        Major = $name.Substring(0,4) ;                                                                          # Stores the Major
        Department = $Majors[$name.Substring(0,4)] ;                                                            # Stores the Department
        UTM = "{0}_UTM" -f $Majors[$name.Substring(0,4)] ;                                                      # Stores the UTM Group
        Instructor = "{0}_{1}_{2}_FAC" -f $name.Substring(0,4),$name.Substring(4,4),$name.Substring(8,3) ;      # Stores the Instructor Group
        Faculty = "{0}_Faculty" -f $Majors[$name.Substring(0,4)];                                               # Sets the Faculty group which is Department Faculty
        SharedName = "{0} {1} Year Shared" -f $Majors[$name.Substring(0,4)],$year ;                           # Shared Folder                                                          # The folder for that this class should be shared with
    };
}
<#
    IncrementalStat
    Checks to see if this stat key exists it it does not it will create it and set it to 1
    Otherwise it incrementals an existing key

    $Key        Key to check for
#>
function IncrementStatKey($Key)
{
    if ($Stats.ContainsKey($Key)) { $Stats[$Key]++; }
    else { $Stats[$Key] = 1; }
}

# Traps Any Errors
trap {
    Write-Output "Error Occurred: $_"; 
    Write-Output "Terminating Execution";
    $_

    if ($SendingEmail -or $Compare -eq $true) { continue }    # In non-compare mode if a serious error occurres we dump
    else { Exit 1 }                                          # if we're in comparison mode the Get-ACL will fail if the folder doesn't exist so we just truck through it
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
Write-Output "Importing OIT User File"
$users = Import-Csv $OITFile -Header  "Givenname","MiddleName","Surname","SamAccountName","Year","Major",
                                   "Password","Class1","Class2","Class3","Class4","Class5","Class6",
                                   "Class7","Class8","Class9","Class10" -Delimiter ';' |                    # Import the file with the given headers as properties
         add-member -membertype "ScriptProperty" -name Department -Value { 
             if (!$Majors.ContainsKey($this.Major)) { $Majors["CADC"] }                                     # If user's major doesn't exist dump them to CADC Major
             else { $Majors[$this.Major] }                                                                  # Otherwise give them to their respective department
         } -PassThru # Add a department field to these students based on their major

# We collapse down the csv file into user and class objects and perform the necessary operations
$Class_Users = @{}                                                                                          # Holds a list of all classes and the users which are in them
$Stats = @{}                                                                                                # Holds statistics about this run of the script
$Start = Get-Date                                                                                           # Used to time how long it takes
Write-Output ("Start {0}" -f (Get-Date))
foreach ($user in $users) {                                                                                 # For every user
    # Loop through users classes and add unique ones to our big list
    # We do some shady stuff and retreive all of the properties labeled Class* then load them into an array of classes
    $MyClasses = $user | get-member -Name "Class*" | select -ExpandProperty Definition |                    # Get all the properties in the format of Class*
                    foreach { $_.Substring($_.IndexOf("=")+1) } |                                           # Get anything After the = sign (they are in the format Class#=ClassName)
                    where { $_.Length -gt 1 -and $Majors.ContainsKey($_.Substring(0,4)) } |                 # Get any which have a length > 1 (aka existed) and are in our major
                    foreach { FormatClass $_ }                                                              # Return a class object for each of the classes 
    if ($MyClasses -ne $null) {                                                                             # Does this user have any classes?
        foreach ($Class in $MyClasses) {                                                                    # if so lets loop through them
            if (!$Class_users.ContainsKey($Class.FormattedName))  {                                         # Have we seen this class before?
                $Empty_Array = New-Object System.Collections.ArrayList                                      # Create an empty array (the long way)
                $Class_Users.Add($Class.FormattedName,$Empty_Array);                                        # Add the class name and empty list to our Class_Users object
                IncrementStatKey ("{0} Classes" -f $Class.Department)

                if ($Vebrose) { Write-Output ("Found New Class: {0}" -f $Class.Name) }                              # Tell you about it if vebrose mode is on
            }
        }
    }

    # Get a list of our classes but only the formatted names
    $Class_Names = $MyClasses | % { $_.FormattedName }

    # Here we build the LDAP_OU and Check if this user is someone we should proceed with or not
    if (!$Majors.ContainsKey($user.Major) -and ($MyClasses -eq $null -or $MyClasses.Count -eq $null -or $MyClasses.Count -eq 0)) {                                    # The user is not declared one of our majors, we need to see if they are takingany of our classes
        continue                                                                                            # Nor our they in any of our clases, ditch the freaks :)
    }
    else { IncrementStatKey ("{0} Students" -f $user.Department) }                                               # If the user is in our majors then we make sure we note this in our statistics
    $LDAP_OU = "OU={0},{1}" -f $user.Department,$LDAP                                                       # We use the $user.Department to determine where to store them
    $username = $user.SamAccountName                                                                        # Stupid fix for powershell AD Filters (can't access a property of PSCustomObject directly)

    # Here we either create the user or retrieve the User AD object
    $UserAD = Get-ADUser -Filter { Name -eq $username }                                                     # Attempt to retreive the user from the ad
    if ($UserAD -eq $null)                                                                                  # If the user doesn't exist
    {
        $UserAD = New-ADUser $user.SamAccountName -SamAccountName $user.SamAccountName `
                                    -GivenName $user.GivenName -Surname $user.Surname -Department $user.Department `
                                    -AccountPassword $UserPassword -Enabled $false -ScriptPath 'SLOGIC' `
                                    -DisplayName ("{0} {1}" -f $user.GivenName,$user.Surname) `
                                    -Description ("{0} {1}" -f $user.GivenName,$user.Surname) `
                                    -UserPrincipalName ("{0}@{1}" -f $user.SamAccountName,$FullDomain) `
                                    -EmailAddress ("{0}@auburn.edu" -f $user.SamAccountName) `
                                    -AccountExpirationDate $UserExpireDate -Path "OU=Students,$LDAP_OU" `
                                    -ChangePasswordAtLogon:$true -WhatIf:$Compare -PassThru                 # Create the AD Object with the given properties

        IncrementStatKey ("New {0} Students" -f $user.Department)                                           # Adds a new user to our statistic count for this major
        Write-Output ("Creating a new user: {0}" -f $user.SamAccountName)
    }

    # Get Groups and handle dropped classes
    if (!$Compare) { $GroupsAD = Get-ADPrincipalGroupMembership $UserAD }                                   # Retrieves the user's groups
    $Group_Names = $GroupsAD | select -expand name                                                          # Retreives the names of all groups this user is a member of

    # Store list of classes user should add (aka those which were enrolled but are not currently a member)
    $AddedClasses = $Class_Names | where { $Group_Names -notcontains $_  }                                  # Get the groups that we aren't currently in and need to be added to
    if ($AddedClasses -ne $null) {                                                                          # Were there any we need to be added to?    
        foreach ($Add in $AddedClasses) {                                                                   # Lets loop through them
            $Class_Users[$Add].Add($user.SamAccountName) | out-null                                         # Add the user to this class in the list of classes and users

            IncrementStatKey "Students Who Added A Class"
            if ($Vebrose) { Write-Output ("Adding Class: $add for {0}" -f $user.SamAccountName) }             # Tell you about it if vebrose is on
        }
    }

    # Drop the classes that should be dropped (aka those which were a member but are no longer enrolled)
    $DroppedClasses = $GroupsAD | 
                        where { $_.name -match "\w{4}_\d{4}_\d{3}" -and $Class_Names -notcontains $_.name } # Filter the groups by the names that don't exist anymore in our class names list
    if ($DroppedClasses -ne $null) {                                                                        # Should any classes be dropped?
        foreach ($DropAD in $DroppedClasses) {                                                              # If so lets do so
            $DropClass = FormatClass $DropAD.name                                                           # Get a class object for this class
            Remove-ADPrincipalGroupMembership $UserAD -memberOf $DropAD -WhatIf:$Compare -Confirm:$false    # Removes the AD user from the group
            if ($Vebrose) { Write-Output ("Dropping Class: {0} for {1}" -f $DropClass.name,$user.SamAccountName) }     # If vebrose tell you this guy is dropped

            # Check if section was moved and not a full drop
            $New_Section = $AddedClasses | 
                                 where { $_ -match ($DropClass.FormattedName.Substring(0,8)+"*") } |        # if any section matches the prefix sans the section number 
                                 select -First 1                                                            # (only select 1, hopefully they dont join two sections, if so we can't help them)

            if ($New_Section -ne $null) {                                                                   # Did they move to a new section?          
                if (!$Compare) { MoveUserClassSection $user $DropClass (FormatClass $New_Section) }         # If so lets move them
                if ($Vebrose) { Write-Output ("Moved User Section from {0} to {1}" -f $DropClass.Name, $New_Section) }  # If vebrose tell youa bout it
                IncrementStatKey "Students Who Moved Section"
            }
            else {                                                                                          # If its not a section move we must tombstone the class            
                IncrementStatKey "Classes Added to Tombstone"
                if ($Compare) { continue; }                                                                 # If we're comparing then we don't actually need to do anything

                # Remove the ACL
                $UserPath = join-path $ClassFolders[$DropClass.Department] -ChildPath `
                                            ("{0}\{1}" -f $DropClass.FormattedName,$user.SamAccountName)    # Get the path for this user's class folder

                if (!(Test-Path $UserPath)) { continue }                                                    # If the folder doesn't exist don't delete them its fine

                $acl = Get-ACL $UserPath                                                                    # Get the acls for that folder
                $rule = $acl.Access | where { $_.IdentityReference -eq ("$DOMAIN"+$user.SamAccountName) }   # Get the rule which gives the user access
                if ($rule -ne $null) { $acl.RemoveAccessRule($rule) | out-null }                            # If the rule exists remove it
                Set-Acl $acl -Path $UserPath -WhatIf:$Compare                                               # Set the acls

                # Hide the folder
                $UserDir = Get-Item $UserPath                                                               # Get the users folder
                $UserDir.Attributes = $UserDir.Attributes -bor [System.IO.FileAttributes]"hidden"           # Or in the hidden attribute

                # Tombstone Folder
                if (!$Tombstones.Containskey($user.SamAccountName)) {                                       # If the user does not have any other tombstoned folders        
                    $Tombstones.Add($user.SamAccountName,@{});                                              # We creates a tombstone for this user
                }

                # Add a tombstone entry
                $Tombstones[$user.SamAccountName].Add($DropClass.FormattedName, (Get-Date))                      # Add the class name to this users tombstoned list and the current date
                if ($Vebrose) { Write-Output ("Tombstoned class for: {0} in {1}" -f $user.SamAccountName,$DropClass.Name) }  # If vebrose tell you about it
            }
        }
    }

    # Also don't forget we have to recycle courses and handle folders that are done and not added back
    $UserTombstoneClasses = $Tombstones[$user.SamAccountName]                                               # Get the users list of tombstoned classes
    if ($Vebrose) { Write-Output ("Checking tombstoned classes for: {0}" -f $user.SamAccountName) }         # If veborse tell you about it
    if ($UserTombstoneClasses -ne $null) {                                                                  # Does the user have any tombstoned classes
        $UserTombstoneClasses_Clone = $UserTombstoneClasses.Clone()                                         # If so lets clone the list so we can iterate over it while removing items from the original
        foreach ($TombstoneClass in $UserTombstoneClasses_Clone.GetEnumerator()) {                          # Iterate over the cloned list  
            $diff = (Get-Date) - $TombstoneClass.Value                                                      # get the time difference from when the class was tombstoned until now
            if ($diff.TotalDays -gt $TombstoneDays) {                                                       # If the difference is greater than the number of days required
                $ClassObject = FormatClass $TombstoneClass.Key                                              # Create a class object for this tombstoned class
                if (!$Compare) {
                    join-path $ClassFolders[$ClassObject.Department] -ChildPath $TombstoneClass.Key |       # We get the path to the users folder
                        join-path -ChildPath $user.SamAccountName |
                        Remove-Item -Force                                                                  # And remove the item (-Force is required becaues it is a hidden folder)
                }

                if ($Vebrose) { Write-Output ("Removed tombstoned class for user: {0} in class {1}" -f $user.SamAccountName, $TombstoneClass.Key) } # tell you about it

                # Remove from tombstones list (If we're not comparing)
                if (!$Compare) { $UserTombstoneClasses.Remove($TombstoneClass.Key) }                        # Remove this class from the original (non-cloned) list

                IncrementStatKey "Tombstoned Classes Removed"
            }
        }

        if ($UserTombstoneClasses.Count -eq 0) { $Tombstones.Remove($user.SamAccountName) }                 # if user has no more tombstones remove the user from the tombstoned list
    }
}

# Now we focus on creating the classes and added the users to those classes
Write-Output ("Parsed File and Created Users - Time Elapsed {0} Seconds" -f ((Get-Date) - $Start).TotalSeconds)               # tell you how long it took to do part 1
Write-Output "Creating Classes and Adding Users"                                                            # Say what were doing
foreach ($ClassEntry in $Class_Users.GetEnumerator()) {                                                     # Enumerate over every class we have
    $Class = FormatClass $ClassEntry.Key;                                                                   # Get The class object
    $Class_FormattedName = $Class.FormattedName                                                             # Used because the filter syntax doesn't allow hash table access
    if ($Vebrose) { Write-Output ("Working on Class: {0}" -f $Class.Name) }                                          # We say what class were about to work on

    $LDAP_OU = "OU={0},{1}" -f $Class.Department,$LDAP                                                      # Make the LDAP OU once
    $ClassAD = Get-ADGroup -Filter { name -eq $Class_FormattedName } -SearchBase "OU=Classes,$LDAP_OU"      # Retreive the AD Group for the class
    if ($ClassAD -eq $null)                                                                                 # If the class does not already exist
    {
        $ClassAD = CreateClass $Class                                                                       # Lets create it
        Write-Output ("Creating Class: {0}" -f $Class.Name)                                                 # Tell you we're creating a class if in vebrose mode

        IncrementStatKey "New Classes Created"
    }
    else { CreateClassFolders $Class }                                                                      # If we didn't create the class we should check if the class folder exists, this function will create them if it doesnt

    # Add users to class
    if ($Vebrose) { Write-Output ("Adding Users to Class: {0}" -f $Class.Name) }                            # lets add the necessary users to this class
    if ($Class_Users[$Class.FormattedName].Count -gt 0) {                                                   # If this class has any users to be added to it
        foreach ($Username in $Class_Users[$Class.FormattedName]) {                                         # Lets loop through the users
            # Get AD User and add to group
            $UserAD = Get-ADUser -Filter { name -eq $Username }                                             # Gets the AD User (no search-base because this class may not be in  the users major)
            if ($UserAD -eq $null) { continue; }                                                            # If the user doesn't exist lets continue past it
            if (!$Compare) { Add-ADPrincipalGroupMembership $UserAD -MemberOf $ClassAD -WhatIf:$Compare }                 # Adds the user to the class group

            # Check If Tombstoned 
            $UserPath = join-path $ClassFolders[$Class.Department] $Class.FormattedName |                   # Get the users path
                        join-path -ChildPath $Username
            if ($Tombstones.ContainsKey($Username) -and 
                        $Tombstones[$Username].ContainsKey($Class.FormattedName)) {                         # Check if the class is tombstoned for the user
                # Increment stat and check compare
                IncrementStatKey "Tombstoned Classes Revived"
                if ($Compare) { break; }                                                                    # If compare mode lets kick out, no need to be hiding things

                # Unhide the folder                                                                         # If it is lets unhide it and just add the ACL back
                $Dir = Get-Item $UserPath -Force                                                            # Force makes it pick up the hidden folder
                $Dir.Attributes = $Dir.Attributes -band ![System.IO.FileAttributes]"hidden"                 # Remove the hidden attribute

                # Update Tombstone Record
                $Tombstones[$Username].Remove($Class.FormattedName)                                         # Remove this class from the tombstoned list            
                if ($Tombstones[$Username].Count -eq 0) { $Tombstones.Remove($Username) }                   # If the user has no other tombstoned classes remove the user from the tombstoned list

                # Update user
                if ($Vebrose) { Write-Output ("Found Tombstoned Class and User: $Username in {0}" -f $Class.FormattedName) }       # Tell someone about it
            }
            elseif (!(Test-Path $UserPath)) {                                                               # we check to ensure the directory doesn't already exist (perhaps it was moved by MoveClassSection)
                # Create User Directory
                New-Item $UserPath -type directory -WhatIf:$Compare | out-null                              # Create the users directory
                if ($Vebrose) { Write-Output ("Creating User Directory For Class: $Username in {0}" -f $Class.FormattedName) }     # Tell someone about it

                IncrementStatKey "User Directories Created"
            }

            if ($Compare) { continue; }                                                                     # Don't be adding any ACLs to things which don't exist

            # Add the user ACL
            $acl = Get-ACL $UserPath                                                                        # Get the ACLS on the user directory
            $rule = CreateAccessRule $Username "FullControl" $true "Allow"                                  # Create a rule for full control by the user
            $acl.AddAccessRule($rule)                                                                       # Add it
            Set-Acl $acl -Path $UserPath -WhatIf:$Compare                                                   # Set-Acls to the directory
            if ($Vebrose) { Write-Output ("Setting User Folder ACL: $Username in {0}" -f $Class.FormattedName) }       # Tell someonea bout it
        }
    }
}
Write-Output ("Classes Completed in {0} Seconds" -f ((Get-Date) - $Start).TotalSeconds)                     # How long did it takes us?

# Export our tombstones
if (!$Compare -and $Tombstones.Count -gt 0) { Export-Clixml $TombstoneFile -InputObject $Tombstones }       # Do we still have any tombstoned classes, if so serialize the hash table of items
elseif (!$Compare -and (Test-Path $TombstoneFile)) { rm $TombstoneFile }                                    # If not remove the tombstone file

# Inheritance Fix
if (!$Compare -and $DoInheritance) {                                                                        # Should we do the inheritance fixes?
    Write-Output "Doing Inheritance Fix On Top Level Folders"
    foreach ($ServerEntry in $ClassFolders.GetEnumerator()) {                                               # Loop through our top-level folders
        $Server = $ServerEntry.Value
        if ($Server -eq $null) { continue }                                                                 # If for some reason that value doesn't exist lets skip it

        # Get ACLS
        $acl = Get-ACL $Server                                                                              # Get the top levfel path acls
        $acl.SetAccessRuleProtection($true,$false)                                                          # Basically ignore any inherited ACLS

        $DomUser = CreateAccessRule "Domain Users" ("Read","Traverse","ListDirectory") $false "Allow"       # Add a permission for domain users which is not inherited
        $DomAdmin = CreateAccessRule "Domain Admins" "FullControl" $true "Allow"                            # Add a permission for domain admins which gives full control and is inherited
        $System = CreateAccessRule "SYSTEM" "FullControl" $true "Allow" $true                               # Create a SYSTEM permission with full control
        $acl.AddAccessRule($DomUser)
        $acl.AddAccessRule($DomAdmin)
        $acl.AddAccessRule($System)
        Set-ACL $acl -Path $Server -WhatIf:$Compare                                                         # Set the ACLS on the path

        if ($Vebrose) { Write-Output "Inheritance Broken On: $server" }
    }
}

# Mark the OIT File as processed
$NEWFile = ("Processed-{0}.txt" -f (get-date -uformat "%d-%m-%Y-%H%M%S"))                                   # Generate the file name
move-item $OITFile $NEWFile  -WhatIf:$Compare                                                               # Rename the file so that it can be marked as processed and not accidently rerun
if (!$Compare) {                                                                                            # When in compare mode don't do this because the file doesn't exist
    $file = Get-Item $NEWFile                                                                               # Get the new processed file
    $file.Attributes = $UserDir.Attributes -bor [System.IO.FileAttributes]"readonly"                        # Add Readonly
}

# Output Script Information
Write-Output ("Script Completed in {0} Seconds " -f ((Get-Date) - $Start).TotalSeconds)

# Output the statistics
if ($EnableStats) { $Stats }

# Send An EMail if the user wants us to
if (!$NoEmail) {
    $SendingEmail = $true                                                                                   # This is a flag so the trap statement doesn't cause an error just because the send fails
    $message = new-object System.Net.Mail.MailMessage "networkbuilder@cadc.auburn.edu", $AdminEmail, 
                                 "The Network Builder Has Completed", 
                                 ("The Network Builder has completed and been run on {0}.  Please check the log for details" -f (get-date))
    if (!$NoLogging) {
        stop-transcript
        $attachment = New-Object System.Net.Mail.Attachment -ArgumentList ("{0}\builder-{1}.log" -f ((get-location).Path),(get-date -uformat "%m-%d-%Y"))
        $message.Attachments.Add($attachment)
    }

    # Send the email
    $smtp = new-object System.Net.Mail.SmtpClient $EmailServer
    try { 
        $smtp.Send($message) 
        Write-Out ("E-Mail Sent to {0}" -f $AdminEmail)
    }
    catch { Write-Out "Email Sending Failed" }
}
Exit 0
