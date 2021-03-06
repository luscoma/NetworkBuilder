# Resets the directory
rm *_Classes -Force -Confirm:$false -Recurse
mkdir "ARCH_Classes","BSCI_Classes","CADC_Classes","INDD_Classes" | out-null
if (Test-Path tombstone.xml) {
    rm tombstone.xml -Confirm:$false
}

$SubFolders = "Classes","Instructors","Students"
$OUs = "ARCH","BSCI","CADC","INDD"
import-module activedirectory
foreach ($ou in $OUs) {
    foreach ($folder in $SubFolders) {
        $LDAP = "OU={0},OU={1},DC=Test,DC=Local" -f $folder,$ou
        Get-ADObject -Filter { name -like "*" -and ObjectClass -ne "organizationalUnit" } -SearchScope 2 -ResultSetSize $null -SearchBase $LDAP | 
        Remove-ADObject -Confirm:$false     
    }
}

Write-Host "Reset AD and Folders"