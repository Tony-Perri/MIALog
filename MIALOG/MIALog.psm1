<#
    Module for querying the MOVEit Automation REST API 
    /ap1/v1/reports endpoint.

    Works with MOVEit Automation 2019 and later.

    Make sure to install this file and the MIALog.Format.ps1xml
    in a folder named MITLog in your $Env:PSModulePath path.
#>

# Update the format data to display the Log output and paging info   
Update-FormatData -AppendPath "$PSScriptRoot\MIALog.Format.ps1xml"    

# BaseUri for the MOVEit Transfer server
# Will be set by Get-MITToken
$script:BaseUri = ''

# Variable to hold the current Auth Token.
# Will be set by Get-MITToken
$script:Token = @()

function New-MIAToken {
    <#
    .SYNOPSIS
        Create an auth token.
    .DESCRIPTION
        Create an auth token using the /api/v1/token endpoint.
        Call before calling any other Get-MIA* commands.            
    .EXAMPLE
        New-MIAToken
        User is prompted for parameters.
    .EXAMPLE
        New-MIAToken -Hostname 'moveitauto.server.com' -Credential (Get-Credential -Username 'admin')
        Supply parameters on command line except for password.
    .INPUTS
        None.
    .OUTPUTS
        String message if connected.
    .LINK
        See link for /api/v1/token doc.
        https://docs.ipswitch.com/MOVEit/Automation2020/API/REST-API/index.html#_authrequestauthtokenusingpost
    #>
    [CmdletBinding()]
    param (      
        # Hostname for the endpoint                 
        [Parameter(Mandatory=$true)]
        [string]$Hostname,

        # Credentials
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential
    )     

    # Clear any existing Token
    $script:Token = @()

    # Set the Base Uri
    $script:BaseUri = "https://$Hostname/api/v1"
    
    # Build the request
    $uri = "$script:BaseUri/token"
    $params = @{ 
        Method = 'POST'
        ContentType = 'application/x-www-form-urlencoded'        
        Headers = @{Accept = "application/json"}            
    }
    try {                    
        $response = @{
            grant_type = 'password'
            username = $Credential.UserName
            password= $Credential.GetNetworkCredential().Password
            } | Invoke-RestMethod -Uri $uri @params

        if ($response.access_token) {
            $script:Token = @{                    
                AccessToken = $Response.access_token
                CreatedAt = $(Get-Date)
                ExpiresIn = $Response.expires_in
                RefreshToken = $Response.refresh_token
            }
            Write-Output "New MIA Token created for access to $script:BaseUri"
        }
    } 
    catch {
        $_
    }   
}
function Confirm-MIAToken
{
    <#
    .SYNOPSIS
        Confirm an auth token, refresh if necessary.
    .DESCRIPTION
        Determines if the token is expired or expiring within 30 seconds.
        Refreshes an auth token using the /api/v1/token endpoint.
        Called from the Get-MIA* commands.            
    .INPUTS
        None.
    .OUTPUTS
        None.
    .LINK
        See link for /api/v1/token doc.
        https://docs.ipswitch.com/MOVEit/Automation2020/API/REST-API/index.html#_authrequestauthtokenusingpost
    #>    
    [CmdletBinding()]
    param (
    )

    $elapsed = New-TimeSpan -Start $script:Token.CreatedAt
    Write-Verbose "MIA Token at $($elapsed.TotalSeconds.ToString('F0')) of $($script:Token.ExpiresIn) seconds"

    # If the key is within 30 seconds of expiring, let's go ahead and
    # refresh it.
    if ($elapsed.TotalSeconds -gt $script:Token.ExpiresIn - 30) {

        Write-Verbose "MIA Token expired, refreshing..."

        $params = @{
            Uri = "$script:BaseUri/token"
            Method = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Body = "grant_type=refresh_token&refresh_token=$($script:Token.RefreshToken)"
            Headers = @{Accept = "application/json"}
        }
        
        $response = Invoke-RestMethod @params
        if ($response.access_token) {
            $script:Token = @{                    
                AccessToken = $Response.access_token
                CreatedAt = $(Get-Date)
                ExpiresIn = $Response.expires_in
                RefreshToken = $Response.refresh_token
            }
            Write-Verbose "MIA Token refreshed for access to $script:BaseUri"
        }        
    }
}
function Get-MIATaskRun
{
    <#
    .SYNOPSIS
        Get TaskRun log/report.
    .DESCRIPTION
        Get TaskRun log/report using the /api/v1/reports/taskruns endpoint.
        Call New-MIAToken before calling this function
    .EXAMPLE
        Get-MIATaskRun
        Get 100 task run items using default query
    .EXAMPLE
        Get-MIATaskRun -Predicate 'Status=in=("Success","Failure")' -MaxCount 10
        Get 10 task run items using a predicate in rsql format
    .EXAMPLE
        Get-MIATaskRun -StartTimeStart (Get-Date).Date -Status Success,Failure
        Get 100 task run items for today with a status of Success or Failure
    .INPUTS
        None.
    .OUTPUTS
        Collection of task run records as custom MIAReportTaskRun objects.
    .LINK
        See link for /api/v1/reports/taskruns doc.
        https://docs.ipswitch.com/MOVEit/Automation2020/API/REST-API/index.html#_gettaskrunsreportusingpost.
    .NOTES
        Calls Confirm-MIAToken to auto-refresh token.
        Use -verbose parameter to see the rsql predicate.        
    #>
    [CmdletBinding(DefaultParameterSetName='Predicate')]
    param (
        # predicate for REST call
        [Parameter(Mandatory=$false, ParameterSetName='Predicate')]
        [ValidateNotNullOrEmpty()]
        [string]$Predicate = 'Status=in=("Success","Failure")',

        # Filter by taskname ==, =like=. Accepts * and ? for wildcards.
        # Filter by tasknames =in=.
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Taskname,

        # Filter by status(s) ==, =in=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateSet('Success', 'Failure', 'No xfers')]
        [string[]]$Status,

        # Filter by startTime =gt=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartTimeStart,

        # Filter by startTime =le=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartTimeEnd,

        # Filter by filesSent =ge=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [int]$FilesSent,

        # Filter by totalBytesSent =ge=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [int64]$TotalBytesSent,

        # orderBy for REST call
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$OrderBy = '!StartTime',

        #maxCount for REST call
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100000)]
        [int32]$MaxCount = 100
    )

    # Build the predicate based on the params passed in if
    # the BuildRsql param set was used.
    if ($PSCmdlet.ParameterSetName -eq 'BuildRsql') {         
        $Predicate = $(
            switch ($PSBoundParameters.Keys) {
                Taskname {
                    if ($Taskname.Count -gt 1) {
                        'Taskname=in=("{0}")' -f ($Taskname -join '","')
                    }
                    elseif ($Taskname -match '[\*\?]') {                        
                        'Taskname=like="{0}"' -f $Taskname -replace '\*', '%' -replace '\?', '_'
                    }
                    else {
                        'Taskname=="{0}"' -f $Taskname
                    }
                }
                Status {
                    if ($Status.Count -gt 1) {
                        'Status=in=("{0}")' -f ($Status -join '","')
                    }
                    else {
                        'Status=="{0}"' -f $Status
                    }
                }
                StartTimeStart {
                    'StartTime=ge={0:yyyy-MM-ddTHH:mm:ss}' -f $StartTimeStart
                }
                StartTimeEnd {
                    'StartTime=lt={0:yyyy-MM-ddTHH:mm:ss}' -f $StartTimeEnd
                }
                FilesSent {
                    'FilesSent=ge={0}' -f $FilesSent
                }   
                TotalBytesSent {
                    'TotalBytesSent=ge={0}' -f $TotalBytesSent
                }                                 
            } ) -join ';'
    }
    
    Write-Verbose $Predicate
    
    try {        
        # Confirm the Token, refreshing if necessary
        Confirm-MIAToken
        
        # Build the request
        $params = @{
            Uri = "$script:BaseUri/reports/taskruns"
            Method = 'Post'
            Headers = @{
                Accept = 'application/json'
                Authorization = "Bearer $($script:Token.AccessToken)"
            }
            ContentType = 'application/json'
        }

        # Build the request body
        $body = @{
            predicate = "$Predicate";
            orderBy = "$OrderBy";
            maxCount = "$MaxCount"
        } | ConvertTo-Json

        # Invoke the request
        $response = Invoke-RestMethod @params -Body $body
        
        # Add type to the items for better display from .format.ps1xml file and write
        # to the pipeline    
        $response.items | foreach-object { $_.PSOBject.TypeNames.Insert(0, 'MIAReportTaskRun'); $_ }        
    }
    catch {
        $_
    }
}
function Get-MIAFileActivity
{
    <#
    .SYNOPSIS
        Get FileActivity log/report.
    .DESCRIPTION
        Get FileActivity log/report using the /api/v1/reports/fileactivity endpoint.
        Call New-MIAToken before calling this function
    .EXAMPLE
        Get-MIAFileActivity
        Get 100 file activity items using default query
    .EXAMPLE
        Get-MIAFileActivity -Predicate "statuscode==0" -MaxCount 10
        Get 10 file activity items using a predicate in rsql format
    .EXAMPLE
        Get-MIAFileActivity -LogStampStart (Get-Date).Date -Status Success
        Get 100 file activity items for today with a status of Success
    .INPUTS
        None.
    .OUTPUTS
        Collection of file activity records as custom MIAReportFileActivity objects.
    .LINK
        See link for /api/v1/reports/fileactivity doc.
        https://docs.ipswitch.com/MOVEit/Automation2020/API/REST-API/index.html#_getfileactivityreportusingpost.
    .NOTES
        Calls Confirm-MIAToken to auto-refresh token.
        Use -verbose parameter to see the rsql predicate.        
    #>
    [CmdletBinding(DefaultParameterSetName='Predicate')]
    param (
        # predicate for REST call
        [Parameter(Mandatory=$false, ParameterSetName='Predicate')]
        [ValidateNotNullOrEmpty()]
        [string]$Predicate = 'StatusCode=out=("5000","5001")',

        # Filter by taskname(s) ==, =like=, =in=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Taskname,

        # Filter by statuscode ==0, !=0
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateSet('Success', 'Failure')]
        [string]$Status,
        
        # Filter by logStamp =ge=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [datetime]$LogStampStart,

        # Filter by logStamp =lt=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [datetime]$LogStampEnd,
        
        # Filter by action(s) ==, =in=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateSet('get','process', 'send', 'delete', 'rename', 'mkdir')]
        [string[]]$Action,

        # orderBy for REST call
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$OrderBy = '!LogStamp',

        # maxCount for REST call
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100000)]
        [int32]$MaxCount = 100
    )
    
    # Build the predicate based on the params passed in if
    # the BuildRsql param set was used.
    if ($PSCmdlet.ParameterSetName -eq 'BuildRsql') {         
        $Predicate = $(
            switch ($PSBoundParameters.Keys) {
                Taskname {
                    if ($Taskname.Count -gt 1) {
                        'Taskname=in=("{0}")' -f ($Taskname -join '","')
                    }
                    elseif ($Taskname -match '[\*\?]') {                        
                        'Taskname=like="{0}"' -f $Taskname -replace '\*', '%' -replace '\?', '_'
                    }
                    else {
                        'Taskname=="{0}"' -f $Taskname
                    }
                }
                LogStampStart {
                    'LogStamp=ge={0:yyyy-MM-ddTHH:mm:ss}' -f $LogStampStart
                }
                LogStampEnd {
                    'LogStamp=lt={0:yyyy-MM-ddTHH:mm:ss}' -f $LogStampEnd
                }
                Status {
                    if ($Status -eq 'Success') {
                        'StatusCode==0'
                    }
                    elseif ($Status -eq 'Failure') {
                        'StatusCode!=0'
                    }
                }
                Action {
                    if ($Action.Count -gt 1) {
                        'Action=in=({0})' -f ($Action -join '","')
                    }
                    else {
                        'Action=={0}' -f $Action
                    }
                }
            } ) -join ';'
    }

    Write-Verbose $Predicate

    try {
        # Confirm the token, refreshing if necessary
        Confirm-MIAToken

        # Build the request
        $params = @{
            Uri = "$script:BaseUri/reports/fileactivity"
            Method = 'Post'
            Headers = @{
                Accept = 'application/json'
                Authorization = "Bearer $($script:Token.AccessToken)"
            }
            ContentType = 'application/json'
        }

        # Build the request body
        $body = @{
            predicate = "$Predicate"
            orderBy = "$OrderBy"
            maxCount = "$MaxCount"
        } | ConvertTo-Json

        # Invoke the request
        $response = Invoke-RestMethod @params -Body $body
        
        # Add type to the items for better display from .format.ps1xml file and write
        # to the pipeline
        $response.items | foreach-object { $_.PSOBject.TypeNames.Insert(0, 'MIAReportFileActivity'); $_ }
    }
    catch {
        $_
    }
}
function Get-MIAAudit
{
    <#
    .SYNOPSIS
        Get Audit log/report.
    .DESCRIPTION
        Get Audit log/report using the /api/v1/reports/audit endpoint.
        Call New-MIAToken before calling this function
    .EXAMPLE
        Get-MIAAudit
        Get 100 audit items using default query
    .EXAMPLE
        Get-MIAAudit -Predicate "status=='failure'" -MaxCount 10
        Get 10 file activity items using a predicate in rsql format
    .EXAMPLE
        Get-MIAAudit -LogTimeStart (Get-Date).Date -Status Success
        Get 100 audit items for today with a status of Success
    .INPUTS
        None.
    .OUTPUTS
        Collection of audit records as custom MIAReportAudit objects.
    .LINK
        See link for /api/v1/reports/audit doc.
        https://docs.ipswitch.com/MOVEit/Automation2020/API/REST-API/index.html#_getauditreportusingpost
    .NOTES
        Calls Confirm-MIAToken to auto-refresh token.
        Use -verbose parameter to see the rsql predicate.        
    #>
    [CmdletBinding(DefaultParameterSetName='Predicate')]
    param (
        # predicate for REST call
        [Parameter(Mandatory=$false, ParameterSetName='Predicate')]
        [ValidateNotNullOrEmpty()]
        [string]$Predicate = 'Status=="Failure"',

        # Filter by status(s) ==, =in=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateSet('Success', 'Failure')]
        [string[]]$Status,
        
        # Filter by logTime =ge=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [Alias('LogStampStart')]
        [datetime]$LogTimeStart,

        # Filter by logTime =lt=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        [ValidateNotNullOrEmpty()]
        [Alias('LogStampEnd')]
        [datetime]$LogTimeEnd,
        
        # Filter by action(s) ==, =in=
        [Parameter(Mandatory=$false, ParameterSetName='BuildRsql')]
        #[ValidateSet()]
        [string[]]$Action,

        # orderBy for REST call
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$OrderBy = '!LogTime',

        # maxCount for REST call
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100000)]
        [int32]$MaxCount = 100
    )
    
    # Build the predicate based on the params passed in if
    # the BuildRsql param set was used.
    if ($PSCmdlet.ParameterSetName -eq 'BuildRsql') {         
        $Predicate = $(
            switch ($PSBoundParameters.Keys) {
                LogTimeStart {
                    'LogTime=ge={0:yyyy-MM-ddTHH:mm:ss}' -f $LogTimeStart
                }
                LogTimeEnd {
                    'LogTime=lt={0:yyyy-MM-ddTHH:mm:ss}' -f $LogTimeEnd
                }
                Status {
                    if ($Status.Count -gt 1) {
                        'Status=in=("{0}")' -f ($Status -join '","')
                    }
                    else {
                        'Status=="{0}"' -f $Status
                    }
                }
                Action {
                    if ($Action.Count -gt 1) {
                        'Action=in=({0})' -f ($Action -join '","')
                    }
                    else {
                        'Action=={0}' -f $Action
                    }
                }
            } ) -join ';'
    }

    Write-Verbose $Predicate

    try {
        # Confirm the token, refreshing if necessary
        Confirm-MIAToken

        # Build the request
        $params = @{
            Uri = "$script:BaseUri/reports/audit"
            Method = 'Post'
            Headers = @{
                Accept = 'application/json'
                Authorization = "Bearer $($script:Token.AccessToken)"
            }
            ContentType = 'application/json'
        }

        # Build the request body
        $body = @{
            predicate = "$Predicate"
            orderBy = "$OrderBy"
            maxCount = "$MaxCount"
        } | ConvertTo-Json

        # Invoke the request
        $response = Invoke-RestMethod @params -Body $body
        
        # Add type to the items for better display from .format.ps1xml file and write
        # to the pipeline
        $response.items | foreach-object { $_.PSOBject.TypeNames.Insert(0, 'MIAReportAudit'); $_ }
    }
    catch {
        $_
    }
}