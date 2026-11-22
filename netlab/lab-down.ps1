# Stop the network lab: clients, capture, servers; merge the answer keys; remove containers
# and networks. Safe to run after an interrupted start.
#   .\netlab\lab-down.ps1
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
& $py (Join-Path $PSScriptRoot "labctl.py") down
exit $LASTEXITCODE
