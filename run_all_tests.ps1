# Run all algorithms on all datasets and sizes
$datasets = @(
    @{File="Tuesday-WorkingHours.pcap_ISCX.csv"; Dir="results\tue_working_hours_updated"},
    @{File="Wednesday-workingHours.pcap_ISCX.csv"; Dir="results\wed_working_hours_updated"},
    @{File="Monday-WorkingHours.pcap_ISCX.csv"; Dir="results\mon_working_hours_updated"},
    @{File="Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"; Dir="results\thu_morning_webattacks_updated"},
    @{File="Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"; Dir="results\thu_afternoon_infiltration_updated"}
)

$algorithms = @("horspool", "rabin")
$textSizes = @("1MB", "5MB", "10MB", "25MB")
$patternCounts = @(1, 5, 10, 20)
$trials = 5
$patternFile = "signatures.txt"
$executable = ".\ids_runner.exe"

foreach ($dataset in $datasets) {
    $dataFile = $dataset.File
    $resultsDir = $dataset.Dir
    
    if (-not (Test-Path -Path $resultsDir)) {
        New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
    }
    
    foreach ($algo in $algorithms) {
        foreach ($text in $textSizes) {
            foreach ($pc in $patternCounts) {
                $fileStem = "${algo}_${text}_p${pc}"
                $outPath = Join-Path $resultsDir ("$fileStem.csv")
                $logPath = Join-Path $resultsDir ("$fileStem.log")
                Write-Host "Running: $dataFile | algo=$algo | text=$text | patterns=$pc"
                & $executable --algo $algo --data $dataFile --patterns $patternFile `
                    --text-bytes $text --pattern-count $pc --trials $trials `
                    --output $outPath --quiet | Tee-Object -FilePath $logPath
            }
        }
    }
}

Write-Host "All tests completed!"

