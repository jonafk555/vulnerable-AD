<#
.SYNOPSIS
    VulnAD-Extended - Enhanced Vulnerable Active Directory Lab Builder

.DESCRIPTION
    An enhanced fork of the original VulnAD (by wazehell/@safe_buffer) that
    provisions a comprehensive vulnerable Active Directory environment for
    red-team training. Covers the following attack surfaces:

    Baseline (retained from original):
      - Password Spraying / Default Password / Cleartext in Description
      - AS-REP Roasting / Kerberoasting
      - DnsAdmins Abuse / DCSync rights delegation
      - Multi-tier BadACL cross-authorization
      - SMB signing disabled

    Kerberos Delegation:
      - Unconstrained Delegation (computer account)
      - Constrained Delegation - Kerberos Only
      - Constrained Delegation - Protocol Transition (Any Auth)
      - RBCD preconditions (MachineAccountQuota preserved at 10)

    Certificate Attacks:
      - Shadow Credentials preconditions (GenericWrite/All grant)
      - AD CS ESC hints (guided setup if role installed)
      - Certificate chain ACL grants

    Modern Service Accounts:
      - gMSA with excessive permissions (Domain Computers can read secret)
      - dMSA CreateChild rights (Windows Server 2025 only)

    LAPS:
      - Legacy LAPS schema detection
      - Over-privileged LAPS password read access

    Legacy / Weak Settings:
      - Pre-Windows 2000 computer account (predictable password)
      - Reversible Encryption enabled accounts
      - GPP cpassword file planted in SYSVOL

    Coercion Preconditions:
      - Print Spooler service enabled (PrinterBug)
      - EFS service enabled (PetitPotam)
      - DFS Namespace service enabled (DFSCoerce)

    Persistence Preconditions:
      - AdminSDHolder ACL backdoor
      - Multi-hop ACL chain (A -> B -> C -> Domain Admins)

.EXAMPLE
    Invoke-VulnADExtended -DomainName "redteamlab.local" -UsersLimit 100

.EXAMPLE
    Invoke-VulnADExtended -DomainName "redteamlab.local" -SkipADCS -SkipDelegation

.NOTES
    Author: Extended fork of wazehell/@safe_buffer's VulnAD
    For authorized red-team training and isolated lab environments only.
    NEVER run this on any production network.
#>

# ============================================================
# Global data lists
# ============================================================

$Global:HumansNames = @(
    'Aaren','Abbey','Abbie','Abby','Abigail','Ada','Adam','Adan','Adela','Adrian',
    'Aiden','Alan','Albert','Alex','Alexa','Alexander','Alice','Alicia','Alina','Amanda',
    'Amber','Amy','Andrea','Andrew','Angel','Angela','Anna','Anthony','April','Ariana',
    'Ashley','Aubrey','Audrey','Austin','Ava','Barbara','Ben','Benjamin','Bernard','Beth',
    'Betty','Bill','Blake','Bob','Bobby','Brad','Bradley','Brandon','Brenda','Brendan',
    'Brian','Brittany','Bruce','Bryan','Caleb','Cameron','Carl','Carla','Carmen','Carol',
    'Caroline','Carter','Casey','Cassandra','Catherine','Cathy','Cecilia','Charles','Charlie','Charlotte',
    'Chelsea','Cheryl','Chloe','Chris','Christian','Christina','Christine','Christopher','Cindy','Claire',
    'Clara','Clark','Claudia','Clay','Colin','Connor','Corey','Craig','Crystal','Curtis',
    'Cynthia','Daisy','Dale','Dan','Dana','Daniel','Danielle','Danny','Darren','David',
    'Dawn','Dean','Debbie','Deborah','Debra','Denise','Dennis','Derek','Diana','Diane',
    'Dominic','Don','Donald','Donna','Doris','Dorothy','Douglas','Dustin','Dylan','Earl',
    'Ed','Eddie','Edgar','Edith','Edward','Edwin','Elaine','Eleanor','Elena','Eli',
    'Elizabeth','Ella','Ellen','Emily','Emma','Eric','Erica','Erin','Ethan','Eugene',
    'Eva','Evan','Evelyn','Faith','Fatima','Felix','Fernando','Fiona','Frances','Frank',
    'Franklin','Fred','Gabriel','Gabriella','Gail','Gary','Gavin','Gene','George','Georgia',
    'Gerald','Gina','Gladys','Glenn','Gloria','Gordon','Grace','Grant','Greg','Gregory',
    'Hailey','Hannah','Harold','Harry','Hayden','Heather','Helen','Henry','Herbert','Holly',
    'Howard','Hunter','Ian','Ira','Irene','Isaac','Isabella','Isabelle','Ivan','Ivy',
    'Jack','Jackson','Jacob','Jade','James','Jamie','Jane','Janet','Janice','Jason',
    'Jasper','Jay','Jean','Jeff','Jeffrey','Jenna','Jennifer','Jeremy','Jerry','Jesse',
    'Jessica','Jill','Jim','Jimmy','Joan','Joanna','Joe','Joel','John','Johnny',
    'Jon','Jonathan','Jordan','Joseph','Josh','Joshua','Joy','Joyce','Juan','Judith',
    'Judy','Julia','Julian','Julie','June','Justin','Karen','Kate','Katherine','Kathleen',
    'Kathryn','Kathy','Katie','Kayla','Keith','Kelly','Ken','Kenneth','Kevin','Kim',
    'Kimberly','Kirk','Kris','Kristen','Kristin','Kurt','Kyle','Lance','Larry','Laura',
    'Lauren','Lawrence','Lee','Leo','Leonard','Leslie','Lewis','Liam','Lila','Lily',
    'Linda','Lisa','Lloyd','Logan','Lois','Lori','Louis','Louise','Lucas','Lucy',
    'Luis','Luke','Lynn','Madeline','Madison','Mandy','Marc','Marcus','Margaret','Maria',
    'Marie','Marilyn','Mario','Marion','Mark','Martha','Martin','Marvin','Mary','Mason',
    'Matt','Matthew','Maureen','Max','Maxwell','Megan','Melanie','Melissa','Melvin','Michael',
    'Michelle','Miguel','Mike','Miller','Mindy','Miranda','Mitchell','Molly','Monica','Morgan',
    'Nancy','Nathan','Neil','Nicholas','Nicole','Noah','Nora','Norma','Norman','Oliver',
    'Olivia','Oscar','Owen','Pamela','Patricia','Patrick','Paul','Paula','Peggy','Peter',
    'Philip','Phyllis','Rachel','Ralph','Randy','Ray','Raymond','Rebecca','Regina','Renee',
    'Rhonda','Richard','Rick','Ricky','Riley','Rita','Robert','Roberta','Robin','Roger',
    'Ronald','Ronnie','Rose','Ross','Roy','Ruby','Russell','Ruth','Ryan','Sabrina',
    'Sam','Samantha','Samuel','Sandra','Sara','Sarah','Scott','Sean','Sebastian','Sergio',
    'Seth','Shane','Shannon','Sharon','Shawn','Sheila','Shelly','Shirley','Sierra','Simon',
    'Sophia','Sophie','Stanley','Stella','Stephanie','Stephen','Steve','Steven','Sue','Susan',
    'Sylvia','Tabitha','Tammy','Tanya','Tara','Taylor','Ted','Teresa','Terry','Thelma',
    'Theresa','Thomas','Tiffany','Tim','Timothy','Tina','Todd','Tom','Tommy','Tony',
    'Tracy','Travis','Trevor','Tristan','Troy','Tyler','Valerie','Vanessa','Vera','Veronica',
    'Vicki','Victor','Victoria','Vincent','Violet','Virginia','Wade','Walter','Wanda','Warren',
    'Wayne','Wendy','Wesley','Whitney','William','Willie','Wyatt','Xavier','Yolanda','Yvonne',
    'Zachary','Zack','Zoe'
)

$Global:BadPasswords = @(
    'Password1','P@ssw0rd','Summer2025!','Winter2024!','Welcome1!','Company2025!',
    'ncc1701','Changeme123!','Passw0rd!','Admin123!','Letmein1!','Spring2025!',
    'Fall2024!','ChangeMe!','Password123','Qwerty123!','baseball','football',
    'iloveyou','princess','sunshine','superman','master','shadow','hunter',
    'harley','ranger','jordan','jennifer','trustno1','starwars','bailey',
    'welcome','buster','soccer','matrix','freedom','wizard','falcon',
    'silver','forever','purple','banana','summer','winter','autumn'
)

$Global:HighGroups   = @('Office Admin','IT Admins','Executives')
$Global:MidGroups    = @('Senior Management','Project Management','Team Leads')
$Global:NormalGroups = @('Marketing','Sales','Accounting','Support','Research')

$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty')

# Service accounts with SPNs - created as regular users so Kerberoasting works
$Global:ServicesAccountsAndSPNs = @(
    @{Name='svc_mssql';   SPN='MSSQLSvc/sqlserver';     Weak=$true;  Desc='SQL Database Service'},
    @{Name='svc_http';    SPN='HTTP/webserver';         Weak=$false; Desc='Web Application Service'},
    @{Name='svc_exchange';SPN='exchange_svc/mailhost';  Weak=$false; Desc='Exchange Service'},
    @{Name='svc_backup';  SPN='backup_svc/backuphost';  Weak=$false; Desc='Backup Service'},
    @{Name='svc_jenkins'; SPN='jenkins_svc/ci';         Weak=$false; Desc='CI/CD Service'}
)

$Global:CreatedUsers  = @()
$Global:AllObjects    = @()
$Global:Domain        = ''
$Global:DomainDN      = ''
$Global:DomainSid     = ''

# ============================================================
# Output helpers
# ============================================================

$Global:Spacing   = "`t"
$Global:PlusLine  = "`t[+]"
$Global:ErrorLine = "`t[-]"
$Global:InfoLine  = "`t[*]"
$Global:WarnLine  = "`t[!]"

function Write-Good { param($String) Write-Host $Global:PlusLine $String -ForegroundColor Green }
function Write-Bad  { param($String) Write-Host $Global:ErrorLine $String -ForegroundColor Red }
function Write-Info { param($String) Write-Host $Global:InfoLine $String -ForegroundColor Gray }
function Write-Warn { param($String) Write-Host $Global:WarnLine $String -ForegroundColor Yellow }

function ShowBanner {
    $banner = @(
        '',
        '  ============================================================',
        '     VulnAD-Extended - Vulnerable Active Directory (v2.0)',
        '     Original by wazehell/@safe_buffer, Extended edition',
        '     For authorized red-team lab environments only',
        '  ============================================================',
        ''
    )
    $banner | ForEach-Object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','White'))
    }
}

# ============================================================
# Common utility functions
# ============================================================

function VulnAD-GetRandom {
    Param([array]$InputList)
    return Get-Random -InputObject $InputList
}

function VulnAD-CheckPrerequisites {
    Write-Info 'Checking prerequisites...'

    # Check for RSAT / AD PowerShell module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Bad 'ActiveDirectory PowerShell module not found. Install RSAT-AD-PowerShell first.'
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # Verify AD is reachable
    try {
        $null = Get-ADDomain -ErrorAction Stop
    } catch {
        Write-Bad 'Cannot query Active Directory. Run this script on a Domain Controller or a domain-joined host with RSAT installed.'
        return $false
    }

    Write-Good 'Prerequisites OK'
    return $true
}

function VulnAD-GetOSVersion {
    $ver = [System.Environment]::OSVersion.Version
    $build = $ver.Build
    # Windows Server 2025 = build 26100
    # Windows Server 2022 = build 20348
    # Windows Server 2019 = build 17763
    # Windows Server 2016 = build 14393
    return $build
}

function VulnAD-IsServer2025 {
    return (VulnAD-GetOSVersion) -ge 26100
}

function VulnAD-IsADCSInstalled {
    try {
        $ca = Get-WindowsFeature -Name AD-Certificate -ErrorAction Stop
        return $ca.Installed
    } catch {
        return $false
    }
}

function VulnAD-AddACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Destination,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Security.Principal.IdentityReference]$Source,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Rights
    )
    try {
        $ADObject = [ADSI]("LDAP://" + $Destination)
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType]'Allow'
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Source,$adRights,$type,$inheritanceType
        $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ADObject.psbase.CommitChanges()
        return $true
    } catch {
        Write-Bad "AddACL failed: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================
# Baseline functions (retained from original VulnAD)
# ============================================================

function VulnAD-AddADUser {
    Param([int]$Limit = 1)
    Add-Type -AssemblyName System.Web

    for ($i = 1; $i -le $Limit; $i++) {
        $firstname = VulnAD-GetRandom -InputList $Global:HumansNames
        $lastname  = VulnAD-GetRandom -InputList $Global:HumansNames
        $SamAccountName = ("{0}.{1}" -f $firstname, $lastname).ToLower()

        # Skip duplicates
        if ($Global:CreatedUsers -contains $SamAccountName) { continue }

        $upn = "$SamAccountName@$Global:Domain"
        $pwd = [System.Web.Security.Membership]::GeneratePassword(14, 3)

        Write-Info "Creating user: $SamAccountName"
        try {
            New-ADUser -Name "$firstname $lastname" `
                -GivenName $firstname -Surname $lastname `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $upn `
                -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
                -PassThru -ErrorAction Stop | Enable-ADAccount
            $Global:CreatedUsers += $SamAccountName
        } catch {
            Write-Bad "Failed to create ${SamAccountName}: $($_.Exception.Message)"
        }
    }
}

function VulnAD-AddADGroup {
    Param([array]$GroupList)
    foreach ($group in $GroupList) {
        Write-Info "Creating group: $group"
        try { New-ADGroup -Name $group -GroupScope Global -ErrorAction Stop } catch {}
        # Randomly add 3-15 members
        $memberCount = Get-Random -Minimum 3 -Maximum 16
        for ($i = 1; $i -le $memberCount; $i++) {
            $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
            try { Add-ADGroupMember -Identity $group -Members $u -ErrorAction SilentlyContinue } catch {}
        }
        $Global:AllObjects += $group
    }
}

function VulnAD-BadAcls {
    Write-Info 'Building multi-tier BadACL attack paths...'

    # Tier 1: NormalGroup -> MidGroup (perfect for BloodHound exercises)
    foreach ($abuse in $Global:BadACL) {
        $ngroup = VulnAD-GetRandom -InputList $Global:NormalGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        try {
            $Dst = Get-ADGroup -Identity $mgroup
            $Src = Get-ADGroup -Identity $ngroup
            if (VulnAD-AddACL -Source $Src.SID -Destination $Dst.DistinguishedName -Rights $abuse) {
                Write-Info "  [ACL] $ngroup --($abuse)--> $mgroup"
            }
        } catch {}
    }

    # Tier 2: MidGroup -> HighGroup
    foreach ($abuse in $Global:BadACL) {
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        try {
            $Dst = Get-ADGroup -Identity $hgroup
            $Src = Get-ADGroup -Identity $mgroup
            if (VulnAD-AddACL -Source $Src.SID -Destination $Dst.DistinguishedName -Rights $abuse) {
                Write-Info "  [ACL] $mgroup --($abuse)--> $hgroup"
            }
        } catch {}
    }

    # Random mixed ACEs
    $mixed = Get-Random -Minimum 15 -Maximum 26
    for ($i = 1; $i -le $mixed; $i++) {
        $abuse = VulnAD-GetRandom -InputList $Global:BadACL
        $randomuser  = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = VulnAD-GetRandom -InputList $Global:AllObjects
        try {
            if ((Get-Random -Maximum 2)) {
                $Dst = Get-ADUser -Identity $randomuser
                $Src = Get-ADGroup -Identity $randomgroup
            } else {
                $Src = Get-ADUser -Identity $randomuser
                $Dst = Get-ADGroup -Identity $randomgroup
            }
            VulnAD-AddACL -Source $Src.SID -Destination $Dst.DistinguishedName -Rights $abuse | Out-Null
        } catch {}
    }
}

function VulnAD-Kerberoasting {
    Write-Info 'Configuring Kerberoastable service accounts...'
    Add-Type -AssemblyName System.Web

    # Randomly pick one weak-password account from the list
    $weakOne = ($Global:ServicesAccountsAndSPNs | Where-Object { $_.Weak })[0]

    foreach ($svc in $Global:ServicesAccountsAndSPNs) {
        $spn = "$($svc.SPN).$Global:Domain"

        if ($svc.Name -eq $weakOne.Name) {
            $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords
            Write-Warn "  [WEAK] $($svc.Name) with SPN=$spn - password from BadPasswords list"
        } else {
            $pwd = [System.Web.Security.Membership]::GeneratePassword(24, 5)
            Write-Info "  [SAFE] $($svc.Name) with SPN=$spn - random 24-char password"
        }

        try {
            New-ADUser -Name $svc.Name `
                -SamAccountName $svc.Name `
                -UserPrincipalName "$($svc.Name)@$Global:Domain" `
                -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
                -Description $svc.Desc `
                -ServicePrincipalNames @{Add=$spn} `
                -PasswordNeverExpires $true `
                -Enabled $true `
                -ErrorAction Stop
            $Global:CreatedUsers += $svc.Name
        } catch {
            # If already exists, just append the SPN
            try {
                Set-ADUser -Identity $svc.Name -ServicePrincipalNames @{Add=$spn} -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

function VulnAD-ASREPRoasting {
    Write-Info 'Configuring AS-REP roastable accounts...'
    $count = Get-Random -Minimum 3 -Maximum 7
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords
        try {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $true
            Write-Info "  [ASREP] $u - DoesNotRequirePreAuth + weak password"
        } catch {}
    }
}

function VulnAD-DnsAdmins {
    Write-Info 'Populating DnsAdmins group with abusable members...'
    $count = Get-Random -Minimum 2 -Maximum 6
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            Add-ADGroupMember -Identity 'DnsAdmins' -Members $u -ErrorAction SilentlyContinue
            Write-Info "  [DnsAdmins] $u"
        } catch {}
    }
    # Nested group: mid-tier group becomes an indirect DnsAdmins member
    $g = VulnAD-GetRandom -InputList $Global:MidGroups
    try {
        Add-ADGroupMember -Identity 'DnsAdmins' -Members $g -ErrorAction SilentlyContinue
        Write-Info "  [DnsAdmins] Nested group: $g"
    } catch {}
}

function VulnAD-PwdInObjectDescription {
    Write-Info 'Planting cleartext passwords in description/info fields...'
    Add-Type -AssemblyName System.Web
    $count = Get-Random -Minimum 4 -Maximum 8
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $pwd = [System.Web.Security.Membership]::GeneratePassword(12, 2)
        try {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            # Use varied phrasing to mimic real-world sloppy admin comments
            $templates = @(
                "User Password $pwd",
                "temp pw: $pwd (do not delete)",
                "Password for onboarding: $pwd",
                "Reset -> $pwd"
            )
            $desc = VulnAD-GetRandom -InputList $templates
            Set-ADUser $u -Description $desc
            Write-Info "  [Description-Password] $u"
        } catch {}
    }
}

function VulnAD-DefaultPassword {
    Write-Info 'Setting default password on onboarding accounts...'
    $count = Get-Random -Minimum 3 -Maximum 6
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString 'Changeme123!' -AsPlainText -Force)
            Set-ADUser $u -Description 'New user - default password' -ChangePasswordAtLogon $true
            Write-Info "  [DefaultPassword] $u"
        } catch {}
    }
}

function VulnAD-PasswordSpraying {
    Write-Info 'Setting shared password across multiple accounts (spray target)...'
    $shared = 'ncc1701'
    $count = Get-Random -Minimum 8 -Maximum 14
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString $shared -AsPlainText -Force)
            Set-ADUser $u -Description 'Standard user account'
            Write-Info "  [PasswordSpray] $u <- $shared"
        } catch {}
    }
}

function VulnAD-DCSync {
    Write-Info 'Granting DCSync extended rights to random users...'
    $count = Get-Random -Minimum 2 -Maximum 5
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            $ADObject = [ADSI]("LDAP://$Global:DomainDN")
            $sid = (Get-ADUser -Identity $u).SID

            foreach ($guid in @(
                '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
                '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
                '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
            )) {
                $g = New-Object Guid $guid
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$g)
                $ADObject.psbase.Get_objectSecurity().AddAccessRule($ACE)
            }
            $ADObject.psbase.CommitChanges()
            Set-ADUser $u -Description 'Replication Account'
            Write-Info "  [DCSync] $u - granted 3 replication extended rights"
        } catch {}
    }
}

function VulnAD-DisableSMBSigning {
    Write-Info 'Disabling SMB signing on this host (relay-friendly)...'
    try {
        Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -Force
        Write-Good 'SMB signing disabled'
    } catch {}
}

# ============================================================
# Extended functions - Kerberos Delegation
# ============================================================

function VulnAD-UnconstrainedDelegation {
    <#
        Related labs: Unconstrained Delegation + Printer Bug
        Sets TrustedForDelegation on a random member server (or creates
        a placeholder computer account if none exist).
    #>
    Write-Info 'Configuring Unconstrained Delegation on a member server...'

    # Look for non-DC computer accounts
    $candidates = Get-ADComputer -Filter { PrimaryGroupID -ne 516 } -Properties DNSHostName |
                  Where-Object { $_.Enabled }

    if ($candidates) {
        $target = $candidates | Get-Random
        try {
            Set-ADComputer -Identity $target -TrustedForDelegation $true
            Write-Info "  [Unconstrained] $($target.Name)"
        } catch {
            Write-Bad "  Failed to set on $($target.Name)"
        }
    } else {
        # No member servers - create a placeholder computer account
        try {
            New-ADComputer -Name 'SRV-LEGACY' -SamAccountName 'SRV-LEGACY$' `
                -Path "CN=Computers,$Global:DomainDN" `
                -Enabled $true -TrustedForDelegation $true `
                -AccountPassword (ConvertTo-SecureString 'FakeMachinePass2025!' -AsPlainText -Force) `
                -ErrorAction Stop
            Write-Info '  [Unconstrained] Created SRV-LEGACY$ as placeholder'
        } catch {
            Write-Bad "  Could not create placeholder: $($_.Exception.Message)"
        }
    }
}

function VulnAD-ConstrainedDelegation {
    <#
        Related labs: Constrained Delegation (Kerberos Only and Any Auth)
        - svc_iis: Protocol Transition + Constrained (Any Auth)
        - svc_web: Constrained Kerberos Only + weak password (Kerberoastable)
    #>
    Write-Info 'Configuring Constrained Delegation service accounts...'

    Add-Type -AssemblyName System.Web

    # Any Auth (Protocol Transition)
    try {
        $pwd = [System.Web.Security.Membership]::GeneratePassword(20, 4)
        New-ADUser -Name 'svc_iis' -SamAccountName 'svc_iis' `
            -UserPrincipalName "svc_iis@$Global:Domain" `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -Enabled $true -PasswordNeverExpires $true `
            -Description 'IIS App Pool Identity' `
            -ServicePrincipalNames @{Add=@("HTTP/webapp.$Global:Domain")} `
            -ErrorAction Stop

        $target = "CIFS/$(($env:COMPUTERNAME)).$Global:Domain"
        Set-ADUser 'svc_iis' -Add @{ 'msDS-AllowedToDelegateTo' = @($target) }
        Set-ADAccountControl -Identity 'svc_iis' -TrustedToAuthForDelegation $true
        $Global:CreatedUsers += 'svc_iis'
        Write-Info "  [Constrained-AnyAuth] svc_iis -> $target"
    } catch {
        Write-Bad "  svc_iis: $($_.Exception.Message)"
    }

    # Kerberos Only
    try {
        $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords  # weak so it's Kerberoastable
        New-ADUser -Name 'svc_web' -SamAccountName 'svc_web' `
            -UserPrincipalName "svc_web@$Global:Domain" `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -Enabled $true -PasswordNeverExpires $true `
            -Description 'Web frontend service' `
            -ServicePrincipalNames @{Add=@("HTTP/frontend.$Global:Domain")} `
            -ErrorAction Stop

        $target = "CIFS/$(($env:COMPUTERNAME)).$Global:Domain"
        Set-ADUser 'svc_web' -Add @{ 'msDS-AllowedToDelegateTo' = @($target) }
        # No TrustedToAuthForDelegation flag = Kerberos Only
        $Global:CreatedUsers += 'svc_web'
        Write-Info "  [Constrained-KerberosOnly] svc_web -> $target (weak password)"
    } catch {
        Write-Bad "  svc_web: $($_.Exception.Message)"
    }
}

function VulnAD-RBCDPrep {
    <#
        Related labs: RBCD
        1. Preserve default MachineAccountQuota = 10 (low-priv users can create computer accounts)
        2. Grant GenericWrite on computer objects to random users (RBCD entry point)
    #>
    Write-Info 'Preparing RBCD attack surface...'

    # Verify MachineAccountQuota
    try {
        $quota = (Get-ADObject -Identity $Global:DomainDN -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
        if ($null -eq $quota -or $quota -eq 0) {
            Set-ADObject -Identity $Global:DomainDN -Replace @{ 'ms-DS-MachineAccountQuota' = 10 }
            Write-Info '  MachineAccountQuota set to 10'
        } else {
            Write-Info "  MachineAccountQuota already = $quota"
        }
    } catch {
        Write-Bad "  Cannot set MAQ: $($_.Exception.Message)"
    }

    # Grant GenericWrite on up to 5 computer objects to random users
    try {
        $computers = Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Select-Object -First 5
        foreach ($c in $computers) {
            $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
            $Src = Get-ADUser -Identity $u
            if (VulnAD-AddACL -Source $Src.SID -Destination $c.DistinguishedName -Rights 'GenericWrite') {
                Write-Info "  [RBCD-Entry] $u has GenericWrite over $($c.Name)"
            }
        }
    } catch {}
}

function VulnAD-ShadowCredentialsPrep {
    <#
        Related labs: Shadow Credentials
        Grant GenericAll on target computers so the attacker can write to
        msDS-KeyCredentialLink.
    #>
    Write-Info 'Preparing Shadow Credentials attack surface...'
    try {
        $computers = Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Get-Random -Count 2
        foreach ($c in $computers) {
            $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
            $Src = Get-ADUser -Identity $u
            # GenericAll covers writing msDS-KeyCredentialLink
            if (VulnAD-AddACL -Source $Src.SID -Destination $c.DistinguishedName -Rights 'GenericAll') {
                Write-Info "  [ShadowCred-Entry] $u has GenericAll over $($c.Name)"
            }
        }
    } catch {}
}

# ============================================================
# Extended functions - AD CS (ESC series)
# ============================================================

function VulnAD-ADCSVulnerable {
    <#
        Related labs: AD CS ESC1 / ESC4 / ESC7
        Only runs meaningful actions if AD CS is already installed.
        Otherwise prints hints for manual setup.
    #>
    if (-not (VulnAD-IsADCSInstalled)) {
        Write-Warn 'AD CS not installed - skipping ADCS vulnerabilities'
        Write-Warn '  Install with: Install-WindowsFeature AD-Certificate -IncludeManagementTools'
        Write-Warn '  Then: Install-AdcsCertificationAuthority -CAType EnterpriseRootCa'
        return
    }

    Write-Info 'Configuring vulnerable AD CS templates...'

    try {
        # ESC1 requires: Client Authentication EKU + Enrollee Supplies Subject +
        # Domain Users can Enroll. Template ACL manipulation is complex; leave
        # hints for manual/certipy-based validation.
        Write-Info '  [ESC-Hint] Verify with: certipy find -u <user>@<domain> -p <pass> -vulnerable'
        Write-Info '  Or on DC: certutil -catemplates'

        # ESC7: grant a non-admin ManageCA or ManageCertificates on the CA
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            $ca = Get-CertificationAuthority -ErrorAction SilentlyContinue |
                  Where-Object { $_.IsRoot } | Select-Object -First 1
            if ($ca) {
                Write-Warn "  [ESC7-Hint] Manually grant ManageCA/ManageCertificates to $u"
                Write-Warn "    certutil -setreg 'CA\Security' - or use the PSPKI module"
            }
        } catch {}

        Write-Info '  [ADCS] Suggested manual step: duplicate "User" template as "VulnUser"'
        Write-Info '    Enable "Supply in the request" + Client Auth EKU + Domain Users can Enroll'
    } catch {
        Write-Bad "  ADCS setup: $($_.Exception.Message)"
    }
}

# ============================================================
# Extended functions - gMSA / dMSA
# ============================================================

function VulnAD-VulnerableGMSA {
    <#
        Related labs: gMSA overprivilege (Domain Computers can read secret)
    #>
    Write-Info 'Creating gMSA with excessive permissions...'

    # Check KDS Root Key
    $kds = Get-KdsRootKey -ErrorAction SilentlyContinue
    if (-not $kds) {
        try {
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop | Out-Null
            Write-Info '  Created KDS Root Key (backdated for immediate use)'
        } catch {
            Write-Bad "  Cannot create KDS Root Key: $($_.Exception.Message)"
            return
        }
    }

    # gMSA 1: over-privileged - any compromised computer can read the password
    try {
        $existing = Get-ADServiceAccount -Filter { Name -eq 'gmsa_overshare' } -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-ADServiceAccount -Name 'gmsa_overshare' `
                -DNSHostName "gmsa_overshare.$Global:Domain" `
                -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers' `
                -ServicePrincipalNames @("MSSQLSvc/gmsa-sql.$Global:Domain:1433") `
                -ErrorAction Stop
            Write-Warn '  [gMSA-OverPriv] gmsa_overshare - readable by ALL domain computers'
        } else {
            Write-Info '  gmsa_overshare already exists'
        }
    } catch {
        Write-Bad "  gmsa_overshare: $($_.Exception.Message)"
    }

    # gMSA 2: securely scoped (control group)
    try {
        $existing = Get-ADServiceAccount -Filter { Name -eq 'gmsa_secure' } -ErrorAction SilentlyContinue
        if (-not $existing) {
            # Pick a member server, or fall back to a DC as placeholder
            $target = (Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Select-Object -First 1)
            if (-not $target) { $target = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } | Select-Object -First 1 }
            New-ADServiceAccount -Name 'gmsa_secure' `
                -DNSHostName "gmsa_secure.$Global:Domain" `
                -PrincipalsAllowedToRetrieveManagedPassword "$($target.SamAccountName)" `
                -ErrorAction Stop
            Write-Info "  [gMSA-Secure] gmsa_secure - only $($target.Name) can read"
        }
    } catch {
        Write-Bad "  gmsa_secure: $($_.Exception.Message)"
    }
}

function VulnAD-DMSAPrep {
    <#
        Related labs: BadSuccessor (dMSA abuse)
        Only meaningful on Windows Server 2025 (build 26100+).
    #>
    if (-not (VulnAD-IsServer2025)) {
        Write-Warn 'This host is not Server 2025 - dMSA/BadSuccessor conditions cannot be created'
        return
    }

    Write-Info 'Preparing dMSA/BadSuccessor conditions (Server 2025)...'

    try {
        # Create an OU where non-admins can create dMSAs
        $ouPath = "OU=ServiceAccountsOU,$Global:DomainDN"
        $ouExists = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ouPath } -ErrorAction SilentlyContinue
        if (-not $ouExists) {
            New-ADOrganizationalUnit -Name 'ServiceAccountsOU' -Path $Global:DomainDN `
                -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }

        # Grant a mid-tier group CreateChild for msDS-DelegatedManagedServiceAccount
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $Src = Get-ADGroup -Identity $mgroup

        $ou = [ADSI]("LDAP://$ouPath")
        # msDS-DelegatedManagedServiceAccount schemaIDGUID
        $dmsaGuid = New-Object Guid 'a8df7489-c5ea-11d1-bbcb-0080c76670c0'
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Src.SID,
            [System.DirectoryServices.ActiveDirectoryRights]'CreateChild',
            [System.Security.AccessControl.AccessControlType]'Allow',
            $dmsaGuid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
        )
        $ou.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ou.psbase.CommitChanges()

        Write-Warn "  [BadSuccessor] $mgroup can now CreateChild dMSA in $ouPath"
        Write-Warn '  Any member of this group can perform BadSuccessor'
    } catch {
        Write-Bad "  dMSA prep failed: $($_.Exception.Message)"
    }
}

# ============================================================
# Extended functions - LAPS
# ============================================================

function VulnAD-VulnerableLAPS {
    <#
        Related labs: LAPS abuse
        1. Detect Legacy LAPS schema (ms-Mcs-AdmPwd)
        2. Grant a mid-tier group excessive read access to LAPS passwords
    #>
    Write-Info 'Configuring LAPS with over-privileged read access...'

    # Legacy LAPS schema (ms-Mcs-AdmPwd)
    $legacyLaps = Get-ADObject -Filter { Name -eq 'ms-Mcs-AdmPwd' } `
        -SearchBase "CN=Schema,CN=Configuration,$Global:DomainDN" -ErrorAction SilentlyContinue

    if (-not $legacyLaps) {
        Write-Warn '  Legacy LAPS schema not found - install via Update-AdmPwdADSchema (LAPS.x64.msi)'
        Write-Warn '  Or use Windows LAPS: Update-LapsADSchema'
    }

    # Grant a mid-tier group Extended Rights (includes LAPS password read)
    try {
        $computersOU = "CN=Computers,$Global:DomainDN"
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $Src = Get-ADGroup -Identity $mgroup

        $ou = [ADSI]("LDAP://$computersOU")
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Src.SID,
            [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight',
            [System.Security.AccessControl.AccessControlType]'Allow',
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
        )
        $ou.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ou.psbase.CommitChanges()

        Write-Warn "  [LAPS-OverPriv] $mgroup can read LAPS passwords for CN=Computers"
    } catch {
        Write-Bad "  LAPS ACL: $($_.Exception.Message)"
    }
}

# ============================================================
# Extended functions - Legacy weak settings
# ============================================================

function VulnAD-Pre2kComputer {
    <#
        Related labs: Pre-Windows 2000 Compatible Access
        A pre2k computer account's initial password equals the lowercase
        computer name (up to 14 chars, stripped of the trailing $), and
        stays that way if the machine never logs on.
    #>
    Write-Info 'Creating pre-Windows 2000 style computer account with predictable password...'

    $name = 'LEGACYPC'
    try {
        $existing = Get-ADComputer -Filter { Name -eq $name } -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Info "  $name already exists"
            return
        }

        # Password = lowercase computer name (no $)
        $pwd = $name.ToLower()
        New-ADComputer -Name $name `
            -SamAccountName "$name`$" `
            -Path "CN=Computers,$Global:DomainDN" `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Description 'Legacy pre-2000 compatible account' `
            -ErrorAction Stop

        # PasswordNotRequired keeps the initial password from being forcibly rotated
        Set-ADAccountControl -Identity "$name`$" -PasswordNotRequired $true
        Write-Warn "  [Pre2k] $name`$ - password = '$pwd' (predictable, never logged on)"
    } catch {
        Write-Bad "  Pre2k: $($_.Exception.Message)"
    }
}

function VulnAD-ReversibleEncryption {
    <#
        Related labs: Reversible Encryption
        Accounts with reversible encryption store cleartext-recoverable
        secrets - dumpable via secretsdump.
    #>
    Write-Info 'Enabling reversible encryption on random accounts...'
    Add-Type -AssemblyName System.Web
    $count = Get-Random -Minimum 2 -Maximum 4
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $pwd = [System.Web.Security.Membership]::GeneratePassword(14, 3)
        try {
            # Enable AllowReversiblePasswordEncryption
            Set-ADAccountControl -Identity $u -AllowReversiblePasswordEncryption $true
            # Password must be RESET after enabling the flag so it's stored reversibly
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            Write-Warn "  [ReversibleEnc] $u - cleartext recoverable via secretsdump"
        } catch {}
    }
}

function VulnAD-GPPPassword {
    <#
        Related labs: GPP cpassword in SYSVOL
        The AES key used to encrypt GPP cpassword is publicly known
        (Microsoft published it), so any authenticated domain user
        who can read SYSVOL can decrypt these secrets.
    #>
    Write-Info 'Planting GPP cpassword file in SYSVOL...'

    $sysvolPath = "\\$Global:Domain\SYSVOL\$Global:Domain\Policies"
    if (-not (Test-Path $sysvolPath)) {
        Write-Bad "  SYSVOL not accessible at $sysvolPath"
        return
    }

    # Pick an existing GPO directory
    $gpoDir = Get-ChildItem $sysvolPath -Directory | Select-Object -First 1
    if (-not $gpoDir) {
        Write-Bad '  No GPO directory found'
        return
    }

    $prefsDir = Join-Path $gpoDir.FullName 'Machine\Preferences\Groups'
    if (-not (Test-Path $prefsDir)) {
        New-Item -Path $prefsDir -ItemType Directory -Force | Out-Null
    }

    # Publicly known cpassword. The AES key is Microsoft-published; any
    # gpp-decrypt / Get-GPPPassword tool can decode this to the cleartext.
    $cpasswordXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin"
        image="2" changed="2024-01-15 08:30:12" uid="{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}">
    <Properties action="C" fullName="" description="Local admin account"
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
                changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0"
                subAuthority="RID_ADMIN" userName="LocalAdmin"/>
  </User>
</Groups>
'@

    $file = Join-Path $prefsDir 'Groups.xml'
    try {
        $cpasswordXml | Out-File -FilePath $file -Encoding UTF8 -Force
        Write-Warn "  [GPP-cpassword] Groups.xml planted at $file"
        Write-Warn '  Decrypt with: gpp-decrypt <cpassword> (Kali) or Get-GPPPassword (PowerSploit)'
    } catch {
        Write-Bad "  GPP: $($_.Exception.Message)"
    }
}

# ============================================================
# Extended functions - Coercion preconditions
# ============================================================

function VulnAD-CoercionServices {
    <#
        Related labs: Coercion techniques (PrinterBug, PetitPotam, DFSCoerce)
        Ensure the following services are enabled and running so coercion
        attacks are available:
          - Print Spooler  (PrinterBug / MS-RPRN)
          - Encrypting File System  (PetitPotam / MS-EFSR)
          - DFS Namespace  (DFSCoerce / MS-DFSNM)
    #>
    Write-Info 'Ensuring coercion-related services are enabled...'

    $services = @(
        @{Name='Spooler';   Desc='Print Spooler (PrinterBug MS-RPRN)'},
        @{Name='EFS';       Desc='Encrypting File System (PetitPotam MS-EFSR)'},
        @{Name='Dfs';       Desc='DFS Namespace (DFSCoerce MS-DFSNM)'}
    )

    foreach ($svc in $services) {
        try {
            $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($s) {
                Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
                Write-Info "  [Coercion] $($svc.Desc) - enabled"
            }
        } catch {}
    }
}

# ============================================================
# Extended functions - Persistence preconditions
# ============================================================

function VulnAD-AdminSDHolderBackdoor {
    <#
        Related labs: AdminSDHolder persistence
        Grant an ordinary user FullControl on AdminSDHolder. SDProp
        propagates this ACE to all protected objects (DA, EA, etc.)
        approximately every 60 minutes.
    #>
    Write-Info 'Planting AdminSDHolder backdoor ACE...'

    try {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $Src = Get-ADUser -Identity $u
        $target = "CN=AdminSDHolder,CN=System,$Global:DomainDN"

        if (VulnAD-AddACL -Source $Src.SID -Destination $target -Rights 'GenericAll') {
            Write-Warn "  [AdminSDHolder] $u granted GenericAll on AdminSDHolder"
            Write-Warn '  Will propagate to all protected objects on next SDProp run (~60 min)'
        }
    } catch {}
}

function VulnAD-MultiHopACL {
    <#
        Related labs: Multi-hop ACL persistence
        Build a chain: A -> B -> C -> Domain Admins.
        Easy for BloodHound to spot, very hard to notice by manual review.
    #>
    Write-Info 'Building multi-hop ACL chain to Domain Admins...'

    try {
        $userA = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $userB = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $userC = VulnAD-GetRandom -InputList $Global:CreatedUsers

        if ($userA -eq $userB -or $userB -eq $userC -or $userA -eq $userC) {
            Write-Warn '  User collision detected, skipping multi-hop this run'
            return
        }

        $A = Get-ADUser -Identity $userA
        $B = Get-ADUser -Identity $userB
        $C = Get-ADUser -Identity $userC
        $DA = Get-ADGroup -Identity 'Domain Admins'

        # A -> GenericAll -> B
        VulnAD-AddACL -Source $A.SID -Destination $B.DistinguishedName -Rights 'GenericAll' | Out-Null
        # B -> GenericAll -> C
        VulnAD-AddACL -Source $B.SID -Destination $C.DistinguishedName -Rights 'GenericAll' | Out-Null
        # C -> WriteDACL -> Domain Admins
        VulnAD-AddACL -Source $C.SID -Destination $DA.DistinguishedName -Rights 'WriteDacl' | Out-Null

        Write-Warn "  [MultiHopACL] $userA -> $userB -> $userC -> Domain Admins"
    } catch {
        Write-Bad "  MultiHopACL: $($_.Exception.Message)"
    }
}

# ============================================================
# Main function
# ============================================================

function Invoke-VulnADExtended {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,

        [int]$UsersLimit = 100,

        # Selective skip flags
        [switch]$SkipDelegation,
        [switch]$SkipADCS,
        [switch]$SkipGMSA,
        [switch]$SkipDMSA,
        [switch]$SkipLAPS,
        [switch]$SkipLegacy,
        [switch]$SkipCoercion,
        [switch]$SkipPersistence,
        [switch]$SkipSMBSigning
    )

    ShowBanner

    if (-not (VulnAD-CheckPrerequisites)) { return }

    $Global:Domain    = $DomainName
    $Global:DomainDN  = (Get-ADDomain).DistinguishedName
    $Global:DomainSid = (Get-ADDomain).DomainSID.Value

    Write-Info "Domain: $Global:Domain"
    Write-Info "Domain DN: $Global:DomainDN"
    Write-Info "OS Build: $(VulnAD-GetOSVersion)"

    # Weaken default password policy
    Write-Info 'Weakening default password policy...'
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain `
        -LockoutDuration 00:01:00 `
        -LockoutObservationWindow 00:01:00 `
        -LockoutThreshold 0 `
        -ComplexityEnabled $false `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordLength 4

    # === Baseline ===
    VulnAD-AddADUser -Limit $UsersLimit
    Write-Good "Created $UsersLimit users"

    VulnAD-AddADGroup -GroupList $Global:HighGroups
    VulnAD-AddADGroup -GroupList $Global:MidGroups
    VulnAD-AddADGroup -GroupList $Global:NormalGroups
    Write-Good 'Groups created and populated'

    VulnAD-BadAcls
    Write-Good 'BadACL multi-tier paths built'

    VulnAD-Kerberoasting
    Write-Good 'Kerberoasting targets set'

    VulnAD-ASREPRoasting
    Write-Good 'AS-REP roastable accounts set'

    VulnAD-DnsAdmins
    Write-Good 'DnsAdmins populated'

    VulnAD-PwdInObjectDescription
    Write-Good 'Passwords planted in description fields'

    VulnAD-DefaultPassword
    Write-Good 'Default password on onboarding accounts'

    VulnAD-PasswordSpraying
    Write-Good 'Password spray target created'

    VulnAD-DCSync
    Write-Good 'DCSync rights granted'

    # === Extended: Delegation ===
    if (-not $SkipDelegation) {
        VulnAD-UnconstrainedDelegation
        VulnAD-ConstrainedDelegation
        VulnAD-RBCDPrep
        VulnAD-ShadowCredentialsPrep
        Write-Good 'Delegation attack surfaces configured'
    } else { Write-Warn 'Skipped: Delegation' }

    # === Extended: AD CS ===
    if (-not $SkipADCS) {
        VulnAD-ADCSVulnerable
        Write-Good 'AD CS conditions attempted (see hints for manual steps)'
    } else { Write-Warn 'Skipped: ADCS' }

    # === Extended: gMSA ===
    if (-not $SkipGMSA) {
        VulnAD-VulnerableGMSA
        Write-Good 'gMSA over-privilege configured'
    } else { Write-Warn 'Skipped: gMSA' }

    # === Extended: dMSA ===
    if (-not $SkipDMSA) {
        VulnAD-DMSAPrep
    } else { Write-Warn 'Skipped: dMSA' }

    # === Extended: LAPS ===
    if (-not $SkipLAPS) {
        VulnAD-VulnerableLAPS
        Write-Good 'LAPS over-privilege configured'
    } else { Write-Warn 'Skipped: LAPS' }

    # === Extended: Legacy ===
    if (-not $SkipLegacy) {
        VulnAD-Pre2kComputer
        VulnAD-ReversibleEncryption
        VulnAD-GPPPassword
        Write-Good 'Legacy weak configurations planted'
    } else { Write-Warn 'Skipped: Legacy' }

    # === Extended: Coercion preconditions ===
    if (-not $SkipCoercion) {
        VulnAD-CoercionServices
        Write-Good 'Coercion services enabled'
    } else { Write-Warn 'Skipped: Coercion' }

    # === Extended: Persistence preconditions ===
    if (-not $SkipPersistence) {
        VulnAD-AdminSDHolderBackdoor
        VulnAD-MultiHopACL
        Write-Good 'Persistence backdoors planted'
    } else { Write-Warn 'Skipped: Persistence' }

    # === SMB Signing ===
    if (-not $SkipSMBSigning) {
        VulnAD-DisableSMBSigning
    } else { Write-Warn 'Skipped: SMB Signing' }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host '     VulnAD-Extended build complete' -ForegroundColor Green
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host ''
    Write-Info 'Recommended next steps:'
    Write-Info '  1. Snapshot the DC now (baseline)'
    Write-Info '  2. Run BloodHound collection: bloodhound-python -u <any> -p <pass> -d <domain> -ns <dcip> -c All'
    Write-Info '  3. Attempt attacks lab-by-lab against the environment'
    Write-Info '  4. Revert to baseline snapshot between exercises'
    Write-Host ''
    Write-Warn 'Reminder: This environment is INTENTIONALLY vulnerable.'
    Write-Warn 'Never use on any network with real users or production data.'
}

# ============================================================
# Module export
# ============================================================

Export-ModuleMember -Function Invoke-VulnADExtended -ErrorAction SilentlyContinue
