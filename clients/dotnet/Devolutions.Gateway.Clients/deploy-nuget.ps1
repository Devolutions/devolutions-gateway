$path = Get-Location
$ProjectName = Split-Path $path -Leaf
$FullProjectName = Join-Path -Path $path ($ProjectName + ".csproj")
$xml = [xml](Get-Content ($FullProjectName))
$version = $xml.Project.PropertyGroup.Version

try {
    $date = Get-Date
	$year = $date.year
	$month = $date.month
	$day = $date.day

	$split = $version.Split('.');
    $lastnumber = [int]$split[$split.Count - 1]
	$lastnumber = $lastnumber + 1;
	
    $xml.Project.PropertyGroup.Version = "$year.$month.$day.$lastnumber"
    $version = $xml.Project.PropertyGroup.Version
}
catch {
    Write-host 'The .csproj dont contain a version in PropertyGroup'
    pause
    break;
}

$title = $ProjectName + '@' + $version + " ?" 
$question = 'Are you sure you want to proceed?'
$choices = '&No', '&Yes'
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)

if ($decision -eq 1) {
    $xml.Save($FullProjectName)

    dotnet build --configuration Release ($ProjectName + ".csproj")
    dotnet pack --configuration Release ($ProjectName + ".csproj")
	
	Write-host "Build completed, continue with publish?"
	pause

    nuget push -Source "Artifactory" (".\bin\release\" + $ProjectName + "." + $version + ".nupkg")
    nuget push -Source "Artifactory" (".\bin\release\" + $ProjectName + "." + $version + ".snupkg")

    Write-host "done"
}
else {
    Write-Host 'cancelled'
}
pause
