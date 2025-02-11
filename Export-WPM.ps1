Import-Module '.\Identity Authentication\IdentityAuth.psm1'

$global:exportedObjects = @()

function Get-OAuthHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide the OAuth Token')]
        [ValidateNotNullOrEmpty()]
        [string]$BearerToken
    )
    process {
        return @{"Authorization" = "$($BearerToken)"}
    }
}

function Invoke-PostRest {
    param (
        [string]$uri,
        [hashtable]$headers
    )
    return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers
}

function Get-SecuredItemsFromData {
    [CmdletBinding()]
    param (

    )

    begin {
        $uri = "${identityTenantURL}/UPRest/GetSecuredItemsData"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Get-CredsForSecuredItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide Secured Item Key')]
        [ValidateNotNullOrEmpty()]
        [string]$itemKey
    )

    begin {
        $uri = "${identityTenantURL}/UPRest/GetCredsForSecuredItem?sItemkey=${itemKey}"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Get-UPData {
    [CmdletBinding()]
    param (

    )

    begin {
        $uri = "${identityTenantURL}/UPRest/GetUPData"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Get-Apps {
    [CmdletBinding()]
    param (

    )

    begin {
        $uri = "${identityTenantURL}/CBE/GetApps"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Get-MCFA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide the app Key')]
        [ValidateNotNullOrEmpty()]
        [string]$appKey
    )

    begin {
        $uri = "${identityTenantURL}/UPRest/GetMCFA?appkey=${appKey}"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Get-TotpSeedForApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide the app Key')]
        [ValidateNotNullOrEmpty()]
        [string]$appKey
    )

    begin {
        $uri = "${identityTenantURL}/UPRest/GetTotpSeedForApp?appkey=${appKey}"
    }

    process {
        return Invoke-PostRest -uri $uri -headers $header
    }
}

function Format-Totp {
    [CmdletBinding()]
    param (
        [string]$label,
        [string]$t,
        [string]$issuer,
        [string]$digits,
        [string]$algorithm,
        [string]$period

    )

    begin {
        if($label){
            return "otpauth://totp/${label}?secret=${t}&issuer=${issuer}&digits=${digits}&algorithm=${algorithm}&period=${period}"
        }
        else{
            return $t
        }
    }
}

function Get-URLForApp{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide the app Key')]
        [ValidateNotNullOrEmpty()]
        [string]$appKey
    )
    $objApps = Get-Apps
    $objApps.Result.apps|ForEach-Object {
        if($_.AppKey -eq $appKey){
            return $_.url
        }
    }
}

function Add-ToExportedObject {
    [CmdletBinding()]
    param (
        [array]$custom,
        [string]$name,
        [string]$notes,
        [string]$pass,
        [string]$url,
        [string]$username,
        [string]$totpSeed
    )
    begin {
        $exportObject = @{
            custom = (ConvertTo-Json $custom -Compress)
            name = $name
            notes = $notes
            password = $pass
            url = $url
            username = $username
            totp = $totpSeed
        }
    }

    process {
        $global:exportedObjects += New-Object PSObject -Property $exportObject
        Write-Host "Number of objects: $($global:exportedObjects.Count)"
    }
}

$tenantid = Read-Host "Enter Identity Tenant Id"
if($tenantid){
    $identityTenantURL = "https://${tenantid}.id.cyberark.cloud"
}
else{
    Throw "Tenant Id is required"
}

$identityUserName = Read-Host "Enter Identity User Name"
if(-Not $identityUserName){
    Throw "Identity User Name is required"
}
$subdomain = Read-Host "Enter subdomain"
if(-Not $subdomain){
    Throw "Subdomain is required"
}
$BearerToken = (Get-IdentityHeader -IdentityTenantURL $identityTenantURL -IdentityUserName $identityUserName -IdentityTenantId $tenantid -PCloudSubdomain $subdomain).Authorization
if(-Not $BearerToken){
    $BearerToken = Read-Host "Enter the bearer Token"
    if(-Not $BearerToken){
        Throw "Bearer token in required"
    }
}

$header = Get-OAuthHeader -BearerToken $BearerToken


$objSecuredItemsFromData = Get-SecuredItemsFromData

$objSecuredItemsFromData.Result.SecuredItems|ForEach-Object {
    if($_.ItemKey -notmatch "secureditems"){
        #Get-CredsForSecuredItem -itemKey "28d1ed34-2bcf-4399-a92c-7e96f61a193c"
        $obj = Get-CredsForSecuredItem -itemKey $_.ItemKey
        Write-Host "Adding Itemkey for secureditem" $_.ItemKey
        [array]$custom = $obj.result.ce
        [string]$name = $_.name
        [string]$notes = $obj.result.n
        [string]$pass = $obj.result.p
        [string]$username = $obj.result.u
        [string]$url = ""
        [string]$totp = ""
        Write-Host "Initial count: $($global:exportedObjects.Count)"
        Add-ToExportedObject -custom $custom -name $name -notes $notes -pass $pass -url $url -username $username -totpSeed $totp
    }
}

#Get-UPData

$objUPData =  Get-UPData
$objUPData.Result.Apps|ForEach-Object {
    if($_.AppKey -like "@~/apps/*" -or (($_.AppKey -notlike "@/home/*") -and ($_.UsernameStrategy -eq "SetByUser"))){
        #Get-MCFA -appKey "@~/apps/Linkedin"
        $obj = Get-MCFA -appKey $_.AppKey
        $objTotpS = Get-TotpSeedForApp -appKey $_.AppKey
        Write-Host "Adding Itemkey for Apps" $_.AppKey
        [array]$custom = @()
        [string]$name = $_.name
        [string]$notes = ""
        [string]$pass = $obj.result.p
        [string]$username = $obj.result.u
        [string]$url = Get-URLForApp -appKey $_.AppKey
        [string]$totp = ""

        $totp = Format-Totp -label $objTotpS.Result.label -t $objTotpS.Result.t -issuer $objTotpS.Result.issuer -digits $objTotpS.Result.digits -algorithm $objTotpS.Result.algorithm -period $objTotpS.Result.period

        Write-Host "Initial count: $($global:exportedObjects.Count)"
        Add-ToExportedObject -custom $custom -name $name -notes $notes -pass $pass -url $url -username $username -totpSeed $totp
    }
}

Write-Host "Final count: $($global:exportedObjects.Count)"
$global:exportedObjects | Export-Csv -Path .\export.csv -NoTypeInformation
