param([string]$test = "default", [string]$alex)

Write-Host $test
Write-Host $alex

Write-Host "hi"
Write-Host "Press any key to continue ..."

$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
