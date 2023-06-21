param(
    [Parameter(Position=0, mandatory=$true)]
    [string] $LegacyPath,
    [Parameter(Position=1)]
    [string] $RecordingsPath
)

if ([string]::IsNullOrEmpty($RecordingsPath)) {
    $RecordingsPath = Join-Path $Env:ProgramData 'Devolutions\Gateway\recordings'
}

Write-Host "Migrating recordings to '$RecordingsPath'"
$LegacyRecordingIds = Get-ChildItem -Path $LegacyPath -Filter "*.rfo" | ForEach-Object { $_.BaseName }

$LegacyRecordingIds | ForEach-Object {
    $LegacyRecordingId = $_
    $RfoManifestPath = Join-Path $LegacyPath "${LegacyRecordingId}.rfo"
    $rfo = [xml] (Get-Content -Path $RfoManifestPath)
    $ConnectionLogID = $rfo.SessionRecordingInfo.Attributes.Attribute |
        Where-Object { $_.Name -eq 'ConnectionLogID' } | Select-Object -ExpandProperty Value
    Write-Host "Migrating $ConnectionLogID ($LegacyRecordingId)"
    $RecordingSessionPath = Join-Path $RecordingsPath $ConnectionLogID
    $LegacyRecordingFile = Get-Item "${LegacyPath}\${LegacyRecordingId}.*" -Include @("*.webm","*.trp") | Select-Object -First 1
    $RecordingFileType = [System.IO.Path]::GetExtension($LegacyRecordingFile).TrimStart('.')
    $RecordingFileName = "session-0.${RecordingFileType}"
    $FileCreationTime = (Get-Item $LegacyRecordingFile).CreationTime
    $RecordingStartTime = [System.DateTimeOffset]::new($FileCreationTime).ToUnixTimeSeconds()
    $RecordingDuration = 0
    New-Item -Path $RecordingSessionPath -ItemType Directory -Force | Out-Null
    Copy-Item -Path $LegacyRecordingFile -Destination (Join-Path $RecordingSessionPath $RecordingFileName)
    $RecordingManifest = @{
        sessionId = $ConnectionLogID
        startTime = $RecordingStartTime
        duration = $RecordingDuration
        files = @(
            @{
                fileName = $RecordingFileName
                startTime = $RecordingStartTime
                duration = $RecordingDuration
            }
        )
    }
    $RecordingManifestFile = (Join-Path $RecordingSessionPath "recording.json")
    Remove-Item -Path $RecordingManifestFile -ErrorAction SilentlyContinue -Force | Out-Null
    $RecordingManifest | ConvertTo-Json -Depth 3 | Set-Content -Path $RecordingManifestFile -Force
}
