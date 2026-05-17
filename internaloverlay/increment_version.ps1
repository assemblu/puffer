<#
.SYNOPSIS
  Increment the VERSION_BUILD macro in version.h each time the project is built.
.PARAMETER HeaderPath
  Full path to version.h (passed from the pre‑build event).
#>

param(
    [Parameter(Mandatory=$true)][string]$HeaderPath
)

# Read the whole file as a single string
$content = Get-Content -Raw -Path $HeaderPath

# Regex that captures the numeric value after "#define VERSION_BUILD"
if ($content -match '(?m)^(\s*#\s*define\s+VERSION_BUILD\s+)(\d+)(\s*)$') {
    $prefix   = $Matches[1]
    $oldValue = [int]$Matches[2]
    $suffix   = $Matches[3]

    $newValue = $oldValue + 1
    $newLine  = "${prefix}${newValue}${suffix}"

    # Replace only the line that matched (preserves line endings)
    $newContent = $content -replace '(?m)^(\s*#\s*define\s+VERSION_BUILD\s+)\d+(\s*)$', $newLine

    Set-Content -Path $HeaderPath -Value $newContent -Encoding UTF8
    Write-Host "Version updated: $oldValue -> $newValue"
}
else {
    Write-Error "Could not locate '#define VERSION_BUILD' in $HeaderPath"
    exit 1
}
