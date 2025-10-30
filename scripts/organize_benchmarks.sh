# Organize Criterion Benchmark Results
# This script moves benchmark outputs to benches/generated/ and extracts the main report

$ErrorActionPreference = "Stop"

# Paths
$criterionDir = "target\criterion"
$outputDir = "benches\generated"
$reportIndex = "$criterionDir\report\index.html"

# Check if criterion directory exists
if (-not (Test-Path $criterionDir)) {
    Write-Host "No benchmark results found in $criterionDir" -ForegroundColor Yellow
    Write-Host "Run 'cargo bench --all-features' first to generate benchmarks" -ForegroundColor Yellow
    exit 0
}

# Create output directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
}

# Get all subdirectories in criterion except 'report'
$benchmarkDirs = Get-ChildItem -Path $criterionDir -Directory | Where-Object { $_.Name -ne "report" }

if ($benchmarkDirs.Count -eq 0) {
    Write-Host "No benchmark result folders found" -ForegroundColor Yellow
    exit 0
}

Write-Host "`nOrganizing benchmark results..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Move each benchmark folder to generated/
foreach ($dir in $benchmarkDirs) {
    $sourcePath = $dir.FullName
    $destPath = Join-Path $outputDir $dir.Name
    
    # Remove existing directory if it exists
    if (Test-Path $destPath) {
        Remove-Item -Path $destPath -Recurse -Force
        Write-Host "  Removed old: $($dir.Name)" -ForegroundColor Gray
    }
    
    # Move the directory
    Move-Item -Path $sourcePath -Destination $destPath -Force
    Write-Host "  Moved: $($dir.Name) -> $outputDir\" -ForegroundColor Green
}

# Copy the main report index.html to generated/
if (Test-Path $reportIndex) {
    $destReport = Join-Path $outputDir "index.html"
    Copy-Item -Path $reportIndex -Destination $destReport -Force
    
    # Fix the links in index.html to remove '../' prefix
    # Criterion generates links like: href="../aead/..." or href="../aead\..."
    # We need to change them to: href="aead/..." since files are now in same directory
    $htmlContent = Get-Content $destReport -Raw
    
    # Replace ../ prefix in hrefs (handles both forward and back slashes)
    $htmlContent = $htmlContent -replace 'href="\.\./([^"]+)"', 'href="$1"'
    
    # Normalize backslashes to forward slashes for web compatibility
    $htmlContent = $htmlContent -replace '\\', '/'
    
    # Save the fixed HTML
    $htmlContent | Set-Content $destReport -NoNewline
    
    Write-Host "`n  Extracted: report/index.html -> $outputDir\index.html" -ForegroundColor Green
    Write-Host "  Fixed links: removed '../' prefix and normalized paths" -ForegroundColor Green
} else {
    Write-Host "`n  Warning: Main report index.html not found" -ForegroundColor Yellow
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Benchmark organization complete!" -ForegroundColor Green
Write-Host "`nView results:" -ForegroundColor Cyan
Write-Host "  Main report: $outputDir\index.html" -ForegroundColor White
Write-Host "  Individual results: $outputDir\<benchmark_name>\" -ForegroundColor White
Write-Host "`nOpen in browser:" -ForegroundColor Cyan
Write-Host "  Start-Process $outputDir\index.html" -ForegroundColor White
