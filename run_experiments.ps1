Param(
    [string[]]$TextSizes = @('1MB','5MB','10MB','25MB'),
    [int[]]$PatternCounts = @(1,5,10,20),
    [int]$Trials = 5,
    [string]$DataFile = 'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    [string]$PatternFile = 'signatures.txt',
    [string]$ResultsDir = 'results',
    [string]$Algorithm = 'brute',
    [string]$Executable = '.\ids_runner.exe'
)

Push-Location (Split-Path -Parent $PSCommandPath)
try {
    if (-not (Test-Path -Path $ResultsDir)) {
        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    }
    foreach ($text in $TextSizes) {
        foreach ($pc in $PatternCounts) {
            $fileStem = "${Algorithm}_${text}_p${pc}"
            $outPath = Join-Path $ResultsDir ("$fileStem.csv")
            $logPath = Join-Path $ResultsDir ("$fileStem.log")
            Write-Host "Running algo=$Algorithm text=$text patternCount=$pc"
            & $Executable --algo $Algorithm --data $DataFile --patterns $PatternFile `
                --text-bytes $text --pattern-count $pc --trials $Trials `
                --output $outPath --quiet | Tee-Object -FilePath $logPath
        }
    }
}
finally {
    Pop-Location
}

