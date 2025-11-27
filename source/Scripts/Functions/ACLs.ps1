Function Update-ACL {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$FileSystemRights,
        
        [Parameter()]
        [string]$InheritanceFlags = 'ContainerInherit,ObjectInherit',

        [Parameter()]
        [string]$PropagationFlags = 'None',

        [Parameter()]
        [ValidateSet('Allow', 'Deny')]
        $Type = 'Allow'
    )

    If (Test-Path $Path) {
        $NewAcl = Get-ACL -Path $Path
        
        # Handle SID strings by converting to SecurityIdentifier object
        If ($Identity -match '^S-1-\d') {
            Try {
                $SecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($Identity)
                $IdentityReference = $SecurityIdentifier
            }
            Catch {
                Write-Error "Invalid SID format: $Identity"
                return
            }
        }
        Else {
            # Handle account names
            $IdentityReference = $Identity
        }
        
        $FileSystemAccessRuleArgumentList = $IdentityReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $type
        $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FileSystemAccessRuleArgumentList
        $NewAcl.SetAccessRule($FileSystemAccessRule)
        Set-Acl -Path "$Path" -AclObject $NewAcl
    }
}

Function Update-ACLInheritance {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $false, Position = 1)]
        [bool]$DisableInheritance = $false,

        [Parameter(Mandatory = $true, Position = 2)]
        [bool]$PreserveInheritedACEs = $true
    )

    If (Test-Path $Path) {
        $NewACL = Get-Acl -Path $Path
        $NewACL.SetAccessRuleProtection($DisableInheritance, $PreserveInheritedACEs)
        Set-ACL -Path $Path -AclObject $NewACL
    }

}