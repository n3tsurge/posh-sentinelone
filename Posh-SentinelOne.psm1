param(
    [Parameter(Position=0,Mandatory=$true)]
    [string]$Tenant,

    [Parameter(Position=1,Mandatory=$false)]
    [string]$Proxy=$null
)

# The Sentinel One tenant to connect to
$Global:Tenant = $Tenant
# The internal proxy server to use if running this behind a proxy
$Global:Proxy = $Proxy

function Set-S1APIKey
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$APIKey,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [securestring]$MasterPassword
    )

    Begin {
        
    }

    Process {

        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        if(!(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
            Write-Host "Error: Set-S1APIKey must be run as an administrator" -ForegroundColor Red
            return
        }

        $Global:S1APIKey = $APIKey
        $SecureKeyString = ConvertTo-SecureString -String $APIKey -AsPlainText -Force

        # Generate a random secure Salt
        $SaltBytes = New-Object byte[] 32
        $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $RNG.GetBytes($SaltBytes)

        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $EncryptedString = $SecureKeyString | ConvertFrom-SecureString -key $KeyBytes

        $FolderName = 'Posh-SentinelOne'
        $ConfigName = 'api.key'
        $SaltName = 'salt.rnd'

        (Test-Path -Path "$($env:AppData)\$FolderName")
        if (!(Test-Path -Path "$($env:AppData)\$FolderName"))
        {
            Write-Verbose -Message 'Seems this is the first time the config has been set.'
            Write-Verbose -Message "Creating folder $("$($env:AppData)\$FolderName")"
            New-Item -ItemType directory -Path "$($env:AppData)\$FolderName" | Out-Null
        }
        
        Write-Verbose -Message "Saving the information to configuration file $("$($env:AppData)\$FolderName\$ConfigName")"
        "$($EncryptedString)"  | Set-Content  "$($env:AppData)\$FolderName\$ConfigName" -Force

        # Saving salt in to the file.
        Set-Content -Value $SaltBytes -Encoding Byte -Path "$($env:AppData)\$FolderName\$saltname" -Force

        Write-Verbose -Message "Setting file permissions on salt and key file..."

        $paths = @(
            "$($env:AppData)\$FolderName\$ConfigName";
            "$($env:AppData)\$FolderName\$saltname";
        )

        ForEach($path in $paths) {
            Write-Verbose -Message "Setting permissions on $path"
            $acl = Get-Acl $path

            # Remove permission inheritence
            $acl.SetAccessRuleProtection($true,$true) | Out-Null
            Set-Acl -Path $path -AclObject $acl
            $acl = Get-Acl $path

            # Check to see if the accesses are the current user
            # if not, remove the access
            ForEach($access in $acl.access) {
                if($access.IdentityReference.Value -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) {
                    $acl.RemoveAccessRule($access) | Out-Null
                }
            }

            Set-Acl -Path $path -AclObject $acl
        }
        


    }
    End {

    }
}

function Read-S1APIKey {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [securestring]$MasterPassword
    )

    Begin
    {
        # Test if configuration file exists.
        if (!(Test-Path "$($env:AppData)\Posh-Sentinelone\api.key"))
        {
            throw 'Configuration has not been set, Set-S1APIKey to configure the API Keys.'
        }
    }
    Process
    {
        Write-Verbose -Message "Reading key from $($env:AppData)\Posh-SentinelOne\api.key."
        $ConfigFileContent = Get-Content -Path "$($env:AppData)\Posh-SentinelOne\api.key"
        Write-Debug -Message "Secure string is $($ConfigFileContent)"
        $SaltBytes = Get-Content -Encoding Byte -Path "$($env:AppData)\Posh-SentinelOne\salt.rnd" 
        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $SecString = ConvertTo-SecureString -Key $KeyBytes $ConfigFileContent

        # Decrypt the secure string.
        $SecureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
        $APIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)

        # Set session variable with the key.
        Write-Verbose -Message "Setting key $($APIKey) to variable for use by other commands."
        $Global:S1APIKey = $APIKey
        Write-Verbose -Message 'Key has been set.'
    }
    End {

    }
}

function Test-TwoFactor {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$Code,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {}

    Process {}

    End {}
}

function Get-S1Hash {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Hash,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$OSFamily,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$IsBlack,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Limit,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/hashes'
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }

        $urlparams = @{}

        if($IsBlack) {
            $urlparams.Add('is_black', $true)
        }

        if($Limit) {
            $urlparams.Add('limit', $Limit)
        }

        if($OSFamily) {
            $urlparams.Add('os_family', $OSFamily)
        }

        if($Hash) {
            $urlparams.Add('query', $Hash)
        }

        if($urlparams.Count -gt 0) {
            $URI += Set-URLParams $urlparams
        }
    }

    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        if(!$IsBlack) {
            $blacklist = $false
        } else {
            $blacklist = $true
        }

        

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Body', ($Body | ConvertTo-Json))
        $Params.Add('Method', 'Get')
        $Params.Add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
}

function New-S1Hash {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$Hash,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$Description,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$OSFamily,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$IsBlack,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/hashes'
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        if(!$IsBlack) {
            $blacklist = $false
        } else {
            $blacklist = $true
        }
        
        $Body = @{
            'description'=$Description;
            'hash'=$Hash;
            'os_family'=$OSFamily;
            'is_black'=$blacklist;
        }

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Body', ($Body | ConvertTo-Json))
        $Params.Add('Method', 'POST')
        $Params.Add('Uri', $URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            Write-Host "Success" -ForegroundColor Green
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1AgentProcesses {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$AgentName,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?query='+$AgentName
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        $AgentID = $Result.id

        $Params.URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/processes'

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1AgentApplications {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$AgentName,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?query='+$AgentName
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        $AgentID = $Result.id

        $Params.URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/applications'

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1AgentPassphrase {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Query,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/passphrase'
        }

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }

    Process {

        if(!$AgentID) {

            $Params = @{}
            $Params.Add('Query', $Query)
            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }

            if ($APIKey)
            {
                $Params.Add('APIKey', $APIKey)
            }

            $AgentID = (Get-S1Agent @Params).id
            if(!$AgentID) {
                return $null
            }
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/passphrase'
        }

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }
    }
}

function Get-S1Group {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$GroupID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($GroupID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/groups/'+$GroupID
        } else {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/groups'
        }
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1Agents {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Query,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [ValidateSet("unknown","osx","windows","android","linux")]
        [string]$OsType,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Limit=10,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Infected=$false,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/iterator'
        $urlparams = @{
            'limit' = $limit;
        }

        if($Query) {
            $urlparams.add('query', $query)
        }
        if($Infected) {
            $urlparams.add('infected', 'true')
        }
        if($OsType) {
            $urlparams.add('os_type', $OsType)
        }

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }

    Process {
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI + (Set-URLParams $urlparams))
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $agents = @()

        while($true) {
            $Result = Invoke-RestMethod @Params
            $agents += $Result.data
            if($Result.last_id -eq $null) {
                break;
            } else {
                $urlparams.last_id = $Result.last_id
                $Params.URI = $URI + (Set-URLParams $urlparams)
            }
        } 

        return $agents        
    }
}

function Stop-S1AgentScan {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Query,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($Query) {
            $Params = @{}
            $Params.Query = $Query
            if($Proxy) { $Params.Proxy = $Proxy }
            if($ProxyUseDefaultCredentials) { $Params.ProxyUseDefaultCredentials = $ProxyUseDefaultCredentials}
            $agent = Get-S1Agent @Params
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$agent.id+'/abort-scan'
        }
        elseif ($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/abort-scan'
        }
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Post')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
            return $null
        } else {
            Write-Host "Full disk scan aborted on $($agent.network_information.computer_name)"
            return $null
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Invoke-S1AgentScan {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Query,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($Query) {
            $Params = @{}
            $Params.Query = $Query
            if($Proxy) { $Params.Proxy = $Proxy }
            if($ProxyUseDefaultCredentials) { $Params.ProxyUseDefaultCredentials = $ProxyUseDefaultCredentials}
            $agent = Get-S1Agent @Params
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$agent.id+'/initiate-scan'
        }
        elseif ($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID+'/initiate-scan'
        }
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Post')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
            return $null
        } else {
            Write-Host "Full disk scan started on $($agent.network_information.computer_name)"
            return $null
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1Agent {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Query,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Limit=10,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Brief,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($Query) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?query='+$Query+'&limit='+$Limit
        }
        elseif ($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID
        } else {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?limit='+$Limit
        }
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            if($Brief) {
                $details = @{}
                $details.Add('Agent Name', $Result.network_information.computer_name)
                $details.Add('Last Logged In User', $Result.last_logged_in_user_name)

                $Result = New-Object -Type PSObject -Property $details
            }
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Invoke-S1ThreatMitigate {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [string]$ThreatID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true)]
        [ValidateSet("kill","quarantine","un-quarantine","remediate","rollback-remediation")]
        [string]$Action,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {
        $tenant = $Global:Tenant

        $URI = "https://$tenant.sentinelone.net/web/api/v1.6/threats/$ThreatID/mitigate/$Action"

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }

    Process {
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Post')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params 

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
            return $false
        } else {
            if(!$Result) {
                return $true
            } else {
                Write-Host "The threat $ThreatID could not be remediated." -ForegroundColor Red
                return $false
            }
        }

        return $true

        $ErrorActionPreference = $OldEAP 
    }
}

function Set-S1ThreatResolved {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$ThreatID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = "https://$tenant.sentinelone.net/web/api/v1.6/threats/$ThreatID/resolve"

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Post')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params 

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
            return $false
        } else {
            if($Result.status_code -eq 204) {
                return $true
            }
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1Threat {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Open,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$ThreatID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Hash,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [int]$Limit,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Brief,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $urlparams = @{}

        if($AgentID) {
            $urlparams.Add('agent_id', $AgentID);
        }

        if($Limit) {
            $urlparams.Add('limit', $Limit);
        }

        if($Open) {
            $urlparams.Add('resolved', 'false')
        }
        if($Hash) {
            $urlparams.Add('content_hash', $Hash)
        }

        if($ThreatID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/threats/'+$ThreatID
        } else {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/threats'
        }

        if($urlparams.Count -gt 0) {
            $URI += Set-URLParams $urlparams
        }

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params 

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {

            if($Brief) {
                $threats = @()

                $Result | % {
                    
                    $details = @{}
                    $details.Add('id', $_.id)
                    $details.Add('classifier_name', $_.classifier_name)
                    $details.Add('created_date', $_.created_date)
                    $details.Add('display_name', $_.file_id.display_name)
                    $details.Add('hash', $_.file_id.content_hash)
                    $details.Add('agent', $_.agent)

                    $threats += New-Object -Type PSObject -Property $details
                }

                $threats | ft -AutoSize
            } else {
                return $Result
            }
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Invoke-S1IsolateAgent {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentName,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Force,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($AgentName) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?query='+$AgentName
        }
        elseif ($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID
        }

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        if(!$AgentName -and !$AgentID) {
            throw "AgentName or AgentID must be defined"
            return $null
        }


        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if(!$Force) {
            Write-Host "Are you sure you want to perform this action? This host will not be able to connect to the network. Use " -NoNewLine
            Write-Host "Invoke-S1ConnectAgent" -ForegroundColor Yellow -NoNewLine
            Write-Host " to reconnect the agent."
            Write-Host "Performing the `"Isolate Host`" action on target `"$($Result.network_information.computer_name)`"."
            $confirmation = Read-Host "[Y] Yes [N] No"
            if($confirmation -eq "Y") {
                

                $Params.Method = 'Post'
                $Params.Uri = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$Result.id+'/disconnect'

                $Result = Invoke-RestMethod @Params
            } else {
                Write-Host "Operation Cancelled" -ForegroundColor Yellow
                return $null
            }
        } else {
            $Params.Method = 'Post'
            $Params.Uri = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$Result.id+'/disconnect'
            $Result = Invoke-RestMethod @Params
        }

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Invoke-S1ConnectAgent {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentName,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$AgentID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Force,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if ($AgentName) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents?query='+$AgentName
        }
        elseif ($AgentID) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$AgentID
        }

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        if(!$AgentName -and !$AgentID) {
            throw "AgentName or AgentID must be defined"
            return $null
        }


        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if(!$Force) {
            Write-Host "Are you sure you want to perform this action? This host will be placed back on the network."
            Write-Host "Performing the `"Connect Host`" action on target `"$($Result.network_information.computer_name)`"."
            $confirmation = Read-Host "[Y] Yes [N] No"
            if($confirmation -eq "Y") {
                $Params.Method = 'Post'
                $Params.Uri = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$Result.id+'/connect'

                $Result = Invoke-RestMethod @Params
            } else {
                Write-Host "Operation Cancelled" -ForegroundColor Yellow
                return $null
            }
        } else {
            $Params.Method = 'Post'
            $Params.Uri = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/agents/'+$Result.id+'/connect'
            $Result = Invoke-RestMethod @Params
        }

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function Get-S1ThreatForensics {
    [CmdletBinding(DefaultParameterSetName = 'Direct')]

    Param (

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false, Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$ThreatID,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$FormatCSV,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        if($FormatCSV) {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/threats/'+$ThreatID+'/forensics/export/csv'
        } else {
            $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/threats/'+$ThreatID+'/forensics/export/json'
        }
        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }
    Process {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Get')
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params  

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            return $Result
        }

        $ErrorActionPreference = $OldEAP 

    }
    End {

    }
}

function New-S1User {
    [CmdletBinding(DefaultParameterSetName='Manual')]

    Param(
        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Username,

        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$fullName,

        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$Email,

        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [Security.SecureString]$Password,

        [Parameter(ParameterSetName = 'ActiveDirectory',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Admin,

        [Parameter(ParameterSetName = 'ActiveDirectory',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [switch]$Viewer,

        [Parameter(ParameterSetName = 'ActiveDirectory',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Manual',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'ActiveDirectory',
            Mandatory=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$ADUser,

        [Parameter(ParameterSetName = 'ActiveDirectory',
            Mandatory=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false)]
        [string]$ADServer,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy=$Global:Proxy,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin {

        $tenant = $Global:Tenant

        $URI = 'https://'+$tenant+'.sentinelone.net/web/api/v1.6/users'

        if(!(Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            Read-S1APIKey
            $APIKey = $Global:S1APIKey
        } elseif ((Test-Path variable:Global:S1APIKey) -and !($APIKey)) {
            $APIKey = $Global:S1APIKey
        }
    }

    process {


        $userDetails = @{
            "username" = "";
            "full_name" = "";
            "email" = "";
            "password" = "";
            "groups" = @();
        } 

        if($Admin) {
            $userDetails.groups += "Admins"
        } elseif ($Viewer) {
            $userDetails.groups += "Viewers"
        } elseif($Admin -and $Viewer) {
            $userDetails.groups += "Admins"
        } elseif(!$Admin -or !$Viewer) {
            Write-Host "Error: No permission group selected, use the -Admin or -Viewer flag to set the users group." -ForegroundColor Red
        }

        if(!$Password) {
            [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
            $userDetails.password = [System.Web.Security.Membership]::GeneratePassword(15,2)
        }

        if($ADUser) {
            if(!(Get-Command Get-ADUser)) {
                Write-Host "Error: Active Directory Powershell Module not available." -ForegroundColor Red
                return
            } else {

                $ADParams = @{}
                $ADParams.Add('Identity', $ADUser)
                $ADParams.Add('Properties', 'mail')
                if($ADServer) {
                    $ADParams.Add('Server', $ADServer)
                }
                $user = try { Get-ADUser @ADParams } catch { $null }
                if($user) {
                    $userDetails.username = $user.sAMAccountName.ToLower()
                    $userDetails.full_name = $user.givenName + " " + $user.surname
                    $userDetails.email = $user.mail
                    $userDetails.groups += $Group
                } else {
                    Write-Host "Error: User $ADUser not found." -ForegroundColor Red
                    return
                }
            }
        } else {
            Write-Host "Manual User Creation"
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        # Request Headers
        $Headers = @{}
        $Headers.Add('Authorization', 'APIToken '+$APIKey)

        # Build REST parameters
        $Params = @{}
        $Params.Add('Uri', $URI)
        $Params.Add('Method', 'Post')
        $Params.Add('Body', ($userDetails | ConvertTo-Json))
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('ContentType', 'application/json')
        $Params.Add('Headers', $Headers)

         # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        $Result = Invoke-RestMethod @Params

        if($RESTError) {
            Write-Host $RESTError.message -ForegroundColor Red
        } else {
            
            $userId = $Result.id
            if($Admin) {
                Write-Host "User is an Admin, enabling Multi-Factor authentication."
                $Params.Uri = 'https://'+$Global:Tenant+'.sentinelone.net/web/api/v1.6/users/'+$userId+'/2fa/enable'
                $Params.Remove('Body')

                $RESTError = $null
                $Result2 = Invoke-RestMethod @Params

                if($RESTError) {
                    Write-Host $RESTError.message -ForegroundColor Red
                }
            }
            Write-Host "User Created Successfully. Temporary password: $($userDetails.password)"
        }

        $ErrorActionPreference = $OldEAP 
    }
}

function Set-URLParams {
    [CmdletBinding()]
    
    Param(
        [Parameter(Mandatory=$true)]$Parameters
    )

    $parameterString = "";

    ForEach($Parameter in $Parameters.keys) {

        # Check if there is already a first parameter
        # if not set the first parameter
        # if there is use & to join extra parameters
        if($parameterString -match ".*(\?.*=)") {
            $parameterString += "&{0}={1}" -f $Parameter,$Parameters[$Parameter]
        } else {
            $parameterString += "?{0}={1}" -f $Parameter,$Parameters[$Parameter]
        }  
    }
    return $parameterString
}
