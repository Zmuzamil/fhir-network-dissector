# Run every scenario in turn (capture + answer key each), then evaluate them all.
#   .\netlab\generate-captures.ps1                    all scenarios, 5 minutes each (about 25 min)
#   .\netlab\generate-captures.ps1 -Short             all scenarios, 60 s each (quick test)
#   .\netlab\generate-captures.ps1 -Scenarios icu,ward -Duration 120
param(
    [string[]]$Scenarios = @(),
    [int]$Duration = 300,
    [switch]$Short
)
if ($Short) { $Duration = 60 }
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
& $py (Join-Path $PSScriptRoot "labctl.py") generate @Scenarios --duration $Duration
exit $LASTEXITCODE
