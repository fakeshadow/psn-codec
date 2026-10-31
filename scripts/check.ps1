$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $commands = @(
        @('fmt', '--all', '--', '--check'),
        @('clippy', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'),
        @('test', '--all-features', '--locked'),
        @('test', '--no-default-features', '--locked'),
        @('test', '--no-default-features', '--features', 'base64', '--locked'),
        @('+1.88.0', 'test', '--all-features', '--locked'),
        @('+1.88.0', 'check', '--no-default-features', '--features', 'base64', '--locked')
    )
    foreach ($arguments in $commands) {
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw "cargo check failed with exit code $LASTEXITCODE" }
    }
} finally { Pop-Location }
