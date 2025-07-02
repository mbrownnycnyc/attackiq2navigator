# PowerShell script to extract MITRE ATT&CK techniques, detections, and mitigations

param(
    [string]$CTIRepoPath = ".\cti",
    [string]$OutputFilePath = ".\mitre_techniques_data.json"
)

# Check if the CTI repo exists
if (-not (Test-Path -Path $CTIRepoPath)) {
    Write-Error "CTI repository path not found at: $CTIRepoPath"
    exit 1
}

# Define paths
$enterpriseAttackPath = Join-Path -Path $CTIRepoPath -ChildPath "enterprise-attack\enterprise-attack.json"

# Validate enterprise attack path
if (-not (Test-Path -Path $enterpriseAttackPath)) {
    Write-Error "enterprise-attack.json not found at: $enterpriseAttackPath"
    exit 1
}

Write-Host "Loading enterprise-attack.json..." -ForegroundColor Cyan
try {
    $enterpriseAttackData = Get-Content -Path $enterpriseAttackPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse enterprise-attack.json: $_"
    exit 1
}

# Create mappings for techniques
Write-Host "Building technique mappings..." -ForegroundColor Cyan
$techniqueByExternalId = @{}
$techniqueByAttackPatternId = @{}

foreach ($obj in $enterpriseAttackData.objects) {
    if ($obj.type -eq "attack-pattern" -and $obj.external_references) {
        foreach ($ref in $obj.external_references) {
            if ($ref.source_name -eq "mitre-attack" -and $ref.external_id) {
                $techniqueInfo = @{
                    externalId = $ref.external_id
                    attackPatternId = $obj.id
                    name = $obj.name
                    description = if ($obj.PSObject.Properties.Name -contains "description") { $obj.description } else { "" }
                    generic_detection = if ($obj.PSObject.Properties.Name -contains "x_mitre_detection") { $obj.x_mitre_detection } else { "" }
                    detections = @()
                    mitigations = @()
                }
                
                $techniqueByExternalId[$ref.external_id] = $techniqueInfo
                $techniqueByAttackPatternId[$obj.id] = $techniqueInfo
                break
            }
        }
    }
}

# Create a lookup for course-of-action objects
Write-Host "Building mitigation lookup..." -ForegroundColor Cyan
$mitigationLookup = @{}
foreach ($obj in $enterpriseAttackData.objects) {
    if ($obj.type -eq "course-of-action") {
        $mitigationLookup[$obj.id] = @{
            id = $obj.id
            name = $obj.name
            description = if ($obj.PSObject.Properties.Name -contains "description") { $obj.description } else { "" }
        }
    }
}

# Process relationship objects directly from enterprise-attack.json
Write-Host "Processing relationships from enterprise-attack.json..." -ForegroundColor Cyan
$relationshipCount = 0

foreach ($obj in $enterpriseAttackData.objects) {
    if ($obj.type -eq "relationship" -and $obj.relationship_type -eq "mitigates") {
        $relationshipCount++
        
        $targetRef = $obj.target_ref
        $sourceRef = $obj.source_ref
        
        # Check if this relationship connects a mitigation to a technique
        if ($techniqueByAttackPatternId.ContainsKey($targetRef) -and $mitigationLookup.ContainsKey($sourceRef)) {
            # Get the contextual description from the relationship object if available
            $contextualDescription = if ($obj.PSObject.Properties.Name -contains "description") { $obj.description } else { $mitigationLookup[$sourceRef].description }
            
            $techniqueByAttackPatternId[$targetRef].mitigations += @{
                name = $mitigationLookup[$sourceRef].name
                description = $contextualDescription
            }
        }
    }
}

Write-Host "Processed $relationshipCount mitigation relationships" -ForegroundColor Cyan

# Define predefined detections for specific techniques
$predefinedDetections = @{
    "T1610" = @(
        @{
            name = "Application Log\Application Log Content"
            description = "Monitor application logs for any unexpected or suspicious container deployment activities through the management API or service-specific logs (e.g., Docker Daemon logs, Kubernetes event logs).`n`nAnalytic 1 - Container creation and start activities in Docker and Kubernetes`n`n<code>sourcetype=docker:daemon OR sourcetype=kubernetes:event`n| where action IN (""create"", ""start"")`n </code>"
        },
        @{
            name = "Container\Container Creation"
            description = "Monitor container creation to detect suspicious or unknown images being deployed. Ensure that only authorized images are being used in the environment, especially in sensitive areas.`n`nAnalytic 1 - Creation of unexpected or unauthorized containers`n`n<code>sourcetype=docker:daemon OR sourcetype=kubernetes:event search action=""create""`n| where image NOT IN (""known_images_list"")`n</code>"
        },
        @{
            name = "Container\Container Start"
            description = "Monitor for the start of containers, especially those not aligned with expected images or known administrative schedules.`n`nAnalytic 1 - Unexpected container starts`n`n<code>sourcetype=docker:daemon OR sourcetype=kubernetes:event search action=""start""`n| where user NOT IN (""known_admins"")`n </code>"
        },
        @{
            name = "Pod\Pod Creation"
            description = "Monitor for newly constructed pods that may deploy a container into an environment to facilitate execution or evade defenses."
        },
        @{
            name = "Pod\Pod Modification"
            description = "Monitor for changes made to pods for unexpected modifications to settings and/or control data that may deploy a container into an environment to facilitate execution or evade defenses."
        }
    )
    # Add other technique IDs as needed
}

# Define valid data source and component combinations
$validCombinations = @{
    "Container" = @("Container Creation", "Container Start")
    "Pod" = @("Pod Creation", "Pod Modification")
    "Application Log" = @("Application Log Content")
}

# Process detection information
Write-Host "Processing detection information..." -ForegroundColor Cyan
foreach ($externalId in $techniqueByExternalId.Keys) {
    $technique = $techniqueByExternalId[$externalId]
    $detectionText = $technique.generic_detection
    
    # Use predefined detections if available for this technique
    if ($predefinedDetections.ContainsKey($externalId)) {
        foreach ($detection in $predefinedDetections[$externalId]) {
            $technique.detections += $detection
        }
        continue  # Skip to next technique since we've added all predefined detections
    }
    
    # Skip if no detection text for further processing
    if ([string]::IsNullOrWhiteSpace($detectionText)) {
        continue
    }
    
    # First, try to extract structured Data Source/Data Component patterns
    $regex = [regex]"(?mi)Data Source:\s*([^\r\n,]+)(?:[^\r\n]*?)Data Component:\s*([^\r\n,]+)(?:[^\r\n]*?)(?:Detection|Monitor|Detect):\s*([^\r\n](?:.|[\r\n])*?(?=(?:Data Source:|$)))"
    $matches = $regex.Matches($detectionText)
    
    $detectionFound = $false
    
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            if ($match.Groups.Count -ge 4) {
                $dataSource = $match.Groups[1].Value.Trim()
                $dataComponent = $match.Groups[2].Value.Trim()
                $detectionDesc = $match.Groups[3].Value.Trim()
                
                $name = "$dataSource\$dataComponent"
                
                $technique.detections += @{
                    name = $name
                    description = $detectionDesc
                }
                
                $detectionFound = $true
            }
        }
    }
    
    # Look for analytics in the text
    $analyticMatches = [regex]::Matches($detectionText, "(?is)Analytic\s*\d+.*?<code>([^<]+)</code>")
    
    if ($analyticMatches.Count -gt 0) {
        foreach ($match in $analyticMatches) {
            $analyticText = $match.Value
            
            # Try to extract a title for the analytic
            $titleMatch = [regex]::Match($analyticText, "(?i)Analytic\s*\d+\s*[-:]\s*([^\r\n<]+)")
            $title = if ($titleMatch.Success) {
                $titleMatch.Groups[1].Value.Trim()
            } else {
                "Analytic"
            }
            
            # Try to determine data source and component from the title
            $dataSource = "Analytic"
            $dataComponent = $title
            
            # Find known data sources in the title
            foreach ($ds in $validCombinations.Keys) {
                if ($title -match [regex]::Escape($ds)) {
                    $dataSource = $ds
                    break
                }
            }
            
            # Find known components in the title
            foreach ($ds in $validCombinations.Keys) {
                foreach ($dc in $validCombinations[$ds]) {
                    if ($title -match [regex]::Escape($dc)) {
                        $dataComponent = $dc
                        $dataSource = $ds  # Ensure matching data source
                        break
                    }
                }
            }
            
            $name = "$dataSource\$dataComponent"
            
            $technique.detections += @{
                name = $name
                description = $analyticText
            }
            
            $detectionFound = $true
        }
    }
    
    # If no analytics found, try to use predefined valid combinations if they're mentioned in the text
    if (-not $detectionFound) {
        foreach ($dataSource in $validCombinations.Keys) {
            if ($detectionText -match [regex]::Escape($dataSource)) {
                foreach ($dataComponent in $validCombinations[$dataSource]) {
                    if ($detectionText -match [regex]::Escape($dataComponent)) {
                        $name = "$dataSource\$dataComponent"
                        
                        # Try to extract a specific section that mentions this combination
                        $pattern = "(?i)(?:[^\r\n.]*$dataSource[^\r\n.]*$dataComponent[^\r\n.]*|[^\r\n.]*$dataComponent[^\r\n.]*$dataSource[^\r\n.]*)([^.]+\.)"
                        $specificMatch = [regex]::Match($detectionText, $pattern)
                        
                        $description = if ($specificMatch.Success) {
                            $specificMatch.Groups[1].Value.Trim()
                        } else {
                            # Use the first paragraph as fallback
                            $firstPara = if ($detectionText -match "^([^\r\n]+)") {
                                $matches[1]
                            } else {
                                $detectionText
                            }
                            $firstPara
                        }
                        
                        $technique.detections += @{
                            name = $name
                            description = $description
                        }
                        
                        $detectionFound = $true
                    }
                }
            }
        }
    }
    
    # If still no detections found, create a generic one
    if (-not $detectionFound) {
        $technique.detections += @{
            name = "Generic\Detection"
            description = $detectionText
        }
    }
}

# Format the results into the requested structure
Write-Host "Formatting results..." -ForegroundColor Cyan
$results = @{}

foreach ($externalId in ($techniqueByExternalId.Keys | Sort-Object)) {
    $technique = $techniqueByExternalId[$externalId]
    
    # Remove any duplicate detections by name
    $uniqueDetections = @{}
    foreach ($detection in $technique.detections) {
        if (-not $uniqueDetections.ContainsKey($detection.name)) {
            $uniqueDetections[$detection.name] = $detection
        }
    }
    
    # Remove any duplicate mitigations by name
    $uniqueMitigations = @{}
    foreach ($mitigation in $technique.mitigations) {
        if (-not $uniqueMitigations.ContainsKey($mitigation.name)) {
            $uniqueMitigations[$mitigation.name] = $mitigation
        }
    }
    
    $results[$externalId] = @{
        techniqueId = $externalId
        name = $technique.name
        description = $technique.description
        generic_detection = $technique.generic_detection
        detections = @($uniqueDetections.Values)
        mitigations = @($uniqueMitigations.Values)
    }
}

# Convert to JSON and save
$results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8