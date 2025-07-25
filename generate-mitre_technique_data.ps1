# PowerShell script to extract MITRE ATT&CK techniques, detections, and mitigations

param(
    [string]$CTIRepoPath = ".\cti",
    [string]$OutputFilePath = ".\mitre_techniques_data_summary.json"
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
                    x_mitre_data_sources = if ($obj.PSObject.Properties.Name -contains "x_mitre_data_sources") { $obj.x_mitre_data_sources } else { @() }
                    generic_detection = if ($obj.PSObject.Properties.Name -contains "x_mitre_detection") { $obj.x_mitre_detection } else { "" }
                    detections = @()
                    mitigations = @()
                    is_subtechnique = if ($obj.PSObject.Properties.Name -contains "x_mitre_is_subtechnique") { $obj.x_mitre_is_subtechnique } else { $false }
                    parent_technique_id = $null
                }
                
                $techniqueByExternalId[$ref.external_id] = $techniqueInfo
                $techniqueByAttackPatternId[$obj.id] = $techniqueInfo
                break
            }
        }
    }
}

# Identify parent-child relationships for subtechniques
foreach ($externalId in $techniqueByExternalId.Keys) {
    if ($externalId -match "^T\d+\.\d+$") {
        $parentId = $externalId -replace "\.\d+$", ""
        if ($techniqueByExternalId.ContainsKey($parentId)) {
            $techniqueByExternalId[$externalId].parent_technique_id = $parentId
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

# Create a lookup for data components (for detections)
Write-Host "Building data component lookup..." -ForegroundColor Cyan
$dataComponentLookup = @{}
foreach ($obj in $enterpriseAttackData.objects) {
    if ($obj.type -eq "x-mitre-data-component") {
        $dataComponentLookup[$obj.id] = @{
            id = $obj.id
            name = $obj.name
        }
    }
}

# Process relationship objects directly from enterprise-attack.json
Write-Host "Processing relationships from enterprise-attack.json..." -ForegroundColor Cyan
$mitigationRelCount = 0
$detectionRelCount = 0

foreach ($obj in $enterpriseAttackData.objects) {
    if ($obj.type -eq "relationship") {
        # Process mitigations
        if ($obj.relationship_type -eq "mitigates") {
            $mitigationRelCount++
            
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
        
        # Process detections - THIS IS THE NEW CODE TO HANDLE DETECTIONS
        elseif ($obj.relationship_type -eq "detects") {
            $detectionRelCount++
            
            $targetRef = $obj.target_ref
            $sourceRef = $obj.source_ref
            
            # Check if this relationship connects a detection to a technique
            if ($techniqueByAttackPatternId.ContainsKey($targetRef)) {
                $detectionName = "Detection"
                
                # If the source is a data component, use its name
                if ($dataComponentLookup.ContainsKey($sourceRef)) {
                    $dataComponent = $dataComponentLookup[$sourceRef]
                    $parts = $dataComponent.name -split '\\'
                    if ($parts.Length -ge 2) {
                        $detectionName = "$($parts[0])\$($parts[1])"
                    } else {
                        $detectionName = "$($dataComponent.name)\Detection"
                    }
                }
                
                # Get the description from the relationship object
                $detectionDescription = if ($obj.PSObject.Properties.Name -contains "description") { $obj.description } else { "" }
                
                # Add the detection to the technique
                $techniqueByAttackPatternId[$targetRef].detections += @{
                    name = $detectionName
                    description = $detectionDescription
                }
            }
        }
    }
}

Write-Host "Processed $mitigationRelCount mitigation relationships and $detectionRelCount detection relationships" -ForegroundColor Cyan

# Process detection information directly from x_mitre_detection field
Write-Host "Processing detection information..." -ForegroundColor Cyan

foreach ($externalId in $techniqueByExternalId.Keys) {
    $technique = $techniqueByExternalId[$externalId]
    
    # If there's detection information in the generic_detection field and no detections from relationships, create a detection entry
    if (-not [string]::IsNullOrEmpty($technique.generic_detection) -and $technique.detections.Count -eq 0) {
        # Create detection entries based on data sources
        if ($technique.x_mitre_data_sources -and $technique.x_mitre_data_sources.Count -gt 0) {
            # Process each data source and create a detection entry for it
            foreach ($dataSource in $technique.x_mitre_data_sources) {
                # Parse data source to extract main category and component if possible
                if ($dataSource -match "([^:]+):\s*([^:]+)") {
                    $dataSourceMain = $matches[1].Trim()
                    $dataComponent = $matches[2].Trim()
                    $name = "$dataSourceMain\$dataComponent"
                } else {
                    # Handle cases where the format doesn't match the expected pattern
                    $parts = $dataSource.Split(':')
                    if ($parts.Length -ge 2) {
                        $dataSourceMain = $parts[0].Trim()
                        $dataComponent = $parts[1].Trim()
                        $name = "$dataSourceMain\$dataComponent"
                    } else {
                        # For data sources without a clear component
                        $name = "$dataSource\Activity"
                    }
                }
                
                # Add a detection entry using the generic detection text
                $technique.detections += @{
                    name = $name
                    description = $technique.generic_detection
                }
            }
        } 
        # If no data sources but we have detection text, create a generic detection entry
        elseif (-not [string]::IsNullOrEmpty($technique.generic_detection)) {
            $technique.detections += @{
                name = "Generic\Detection"
                description = $technique.generic_detection
            }
        }
    }
    
    # If technique is a subtechnique and has no detections, inherit from parent
    if ($technique.is_subtechnique -and $technique.detections.Count -eq 0 -and $technique.parent_technique_id) {
        $parentTechnique = $techniqueByExternalId[$technique.parent_technique_id]
        if ($parentTechnique -and $parentTechnique.detections.Count -gt 0) {
            foreach ($detection in $parentTechnique.detections) {
                $technique.detections += @{
                    name = "$($detection.name) (Inherited from $($technique.parent_technique_id))"
                    description = $detection.description
                }
            }
        }
    }
    
    # If still no detections but we have generic detection text, create a generic detection entry
    if ($technique.detections.Count -eq 0 -and -not [string]::IsNullOrEmpty($technique.generic_detection)) {
        $technique.detections += @{
            name = "Generic\Detection"
            description = $technique.generic_detection
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