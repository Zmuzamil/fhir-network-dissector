# Start one network-lab scenario with the capture on (like hl7-sim's lab-up.sh).
#   .\netlab\lab-up.ps1 -Scenario icu -Duration 60
param(
    [Parameter(Mandatory = $true)][string]$Scenario,   # general | ward | laboratory | icu
    [int]$Duration = 300                               # client run time in seconds
)
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
& $py (Join-Path $PSScriptRoot "labctl.py") up $Scenario --duration $Duration
exit $LASTEXITCODE
