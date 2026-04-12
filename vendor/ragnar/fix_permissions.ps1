# PowerShell script to fix permissions for Ragnar repository
# This script sets appropriate permissions for the Ragnar project files and directories

Write-Host "Fixing permissions for Ragnar repository..." -ForegroundColor Green

# Get the current directory (should be Ragnar repo root)
$repoPath = Get-Location

# Directories that need write permissions
$writableDirs = @(
    "data",
    "data\networks", 
    "data\logs",
    "data\input",
    "data\intelligence",
    "data\network_data",
    "data\threat_intelligence",
    "config",
    "resources\comments",
    "var\log",
    "web"
)

# Files that need write permissions
$writableFiles = @(
    "data\networks\.last_ssid",
    "config\shared_config.json",
    "config\actions.json"
)

# Set permissions for directories
foreach ($dir in $writableDirs) {
    $fullPath = Join-Path $repoPath $dir
    if (Test-Path $fullPath) {
        Write-Host "Setting permissions for directory: $dir" -ForegroundColor Yellow
        try {
            # Remove read-only attribute recursively
            Get-ChildItem -Path $fullPath -Recurse -Force | ForEach-Object {
                if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                    $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                }
            }
            
            # Set full control for current user
            $acl = Get-Acl $fullPath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $fullPath -AclObject $acl
            Write-Host "✅ Fixed permissions for $dir" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Failed to set permissions for $dir`: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Creating directory: $dir" -ForegroundColor Cyan
        try {
            New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
            Write-Host "✅ Created directory $dir" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Failed to create directory $dir`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Set permissions for specific files
foreach ($file in $writableFiles) {
    $fullPath = Join-Path $repoPath $file
    $parentDir = Split-Path $fullPath -Parent
    
    # Create parent directory if it doesn't exist
    if (-not (Test-Path $parentDir)) {
        Write-Host "Creating parent directory for: $file" -ForegroundColor Cyan
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
    }
    
    # Create file if it doesn't exist
    if (-not (Test-Path $fullPath)) {
        Write-Host "Creating file: $file" -ForegroundColor Cyan
        try {
            New-Item -Path $fullPath -ItemType File -Force | Out-Null
        }
        catch {
            Write-Host "❌ Failed to create file $file`: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }
    
    Write-Host "Setting permissions for file: $file" -ForegroundColor Yellow
    try {
        # Remove read-only attribute
        $fileItem = Get-Item $fullPath -Force
        if ($fileItem.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $fileItem.Attributes = $fileItem.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
        }
        
        # Set full control for current user
        $acl = Get-Acl $fullPath
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $fullPath -AclObject $acl
        Write-Host "✅ Fixed permissions for $file" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to set permissions for $file`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Fix .gitignore to ensure data files are properly handled
$gitignorePath = Join-Path $repoPath ".gitignore"
if (Test-Path $gitignorePath) {
    Write-Host "Checking .gitignore patterns..." -ForegroundColor Yellow
    $gitignoreContent = Get-Content $gitignorePath -Raw
    
    $requiredPatterns = @(
        "data/networks/.last_ssid",
        "data/logs/*.log",
        "data/networks/*/livestatus.csv",
        "data/networks/*/netkb.csv",
        "*.pyc",
        "__pycache__/",
        ".env"
    )
    
    $modified = $false
    foreach ($pattern in $requiredPatterns) {
        if ($gitignoreContent -notlike "*$pattern*") {
            Write-Host "Adding pattern to .gitignore: $pattern" -ForegroundColor Cyan
            Add-Content -Path $gitignorePath -Value $pattern
            $modified = $true
        }
    }
    
    if ($modified) {
        Write-Host "✅ Updated .gitignore with required patterns" -ForegroundColor Green
    } else {
        Write-Host "✅ .gitignore already contains required patterns" -ForegroundColor Green
    }
}

Write-Host "`n🎉 Permission fix completed!" -ForegroundColor Green
Write-Host "You can now sync these changes to your Raspberry Pi." -ForegroundColor Cyan