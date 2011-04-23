param([string]$test = "default")

Write-Host $test

Write-Host "hi"
"hi"
Write-Host "Press any key to continue ..."

$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
