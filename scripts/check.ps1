$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $commands = @(
        @('fmt', '--all', '--', '--check'),
        @('clippy', '--all-targets', '--all-features', '--locked', '--offline', '--', '-D', 'warnings'),
        @('test', '--all-features', '--locked', '--offline'),
        @('test', '--no-default-features', '--locked', '--offline'),
        @('test', '--no-default-features', '--features', 'base64', '--locked', '--offline'),
        @('+1.88.0', 'test', '--all-features', '--locked', '--offline'),
        @('+1.88.0', 'check', '--no-default-features', '--features', 'base64', '--locked', '--offline')
    )
    foreach ($arguments in $commands) {
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw "cargo check failed with exit code $LASTEXITCODE" }
    }
} finally { Pop-Location }
