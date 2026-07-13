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

    -----------------------------------------------------------------
    Logic-fix revision. Changes vs. the previous version (behavioural
    correctness only; no hardening / no new attack surface):
      1. Password/description-mutating functions now draw from a shared
         RESERVED pool so they no longer collide or overwrite each
         other's planted secrets, and never touch svc_* accounts.
      2. Computer-dependent labs (RBCD / ShadowCred / Unconstrained /
         gMSA_secure) now self-provision a member computer instead of
         silently doing nothing on a fresh single-DC lab.
      3. AddADUser loops until the requested unique count is actually
         reached and reports the real number created.
      4. Domain identity is taken from Get-ADDomain (authoritative);
         -DomainName is validated, not blindly trusted.
      5. Group membership + several samplers now pick distinct members.
    -----------------------------------------------------------------
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
$Global:ReservedUsers = @()   # users already consumed by a password/description-mutating lab
$Global:AllObjects    = @()
$Global:Domain        = ''
$Global:DomainDN      = ''
$Global:DomainSid     = ''

# Marker written to the 'comment' attribute of every user/computer this tool
# creates, so Remove-VulnADExtended can find them even in a fresh session
# (i.e. without relying on the in-memory $Global:CreatedUsers list).
$Global:VulnADTag = 'VULNAD-EXTENDED'

# Fixed-name objects the builder creates. Used by Remove-VulnADExtended so
# cleanup does not depend on runtime state.
$Global:FixedComputers = @('SRV-LEGACY', 'LEGACYPC')
$Global:FixedGMSAs     = @('gmsa_overshare', 'gmsa_secure')
$Global:FixedSvcUsers  = @('svc_iis', 'svc_web') + ($Global:ServicesAccountsAndSPNs | ForEach-Object { $_.Name })
$Global:FixedOUs       = @('ServiceAccountsOU')

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

# Reserve N distinct human users for a password/description-mutating lab.
# Excludes svc_* accounts and any user already reserved by another lab, so
# planted secrets can no longer be silently overwritten by a later function.
function VulnAD-ReserveUsers {
    param([int]$Count)
    $pool = $Global:CreatedUsers | Where-Object {
        $_ -notmatch '^svc_' -and $Global:ReservedUsers -notcontains $_
    }
    if (-not $pool) {
        Write-Warn '  No unreserved users left - skipping this lab'
        return @()
    }
    $take   = [Math]::Min($Count, @($pool).Count)
    $picked = @($pool | Get-Random -Count $take)
    $Global:ReservedUsers += $picked
    return $picked
}

# Return an existing enabled non-DC computer, or create a placeholder one.
# Lets computer-dependent labs work on a fresh single-DC environment instead
# of silently iterating over an empty set.
function VulnAD-EnsureMemberComputer {
    $existing = Get-ADComputer -Filter { PrimaryGroupID -ne 516 } -Properties DNSHostName -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled } | Select-Object -First 1
    if ($existing) { return $existing }

    try {
        $c = New-ADComputer -Name 'SRV-LEGACY' -SamAccountName 'SRV-LEGACY$' `
                -Path "CN=Computers,$Global:DomainDN" -Enabled $true `
                -AccountPassword (ConvertTo-SecureString 'FakeMachinePass2025!' -AsPlainText -Force) `
                -PassThru -ErrorAction Stop
        Write-Info '  Created SRV-LEGACY$ placeholder member computer'
        return $c
    } catch {
        Write-Bad "  Could not create placeholder computer: $($_.Exception.Message)"
        return $null
    }
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

    # Loop until we actually reach the requested number of DISTINCT new users,
    # rather than burning an iteration on every name collision / create error.
    $goal  = $Global:CreatedUsers.Count + $Limit
    $tries = 0
    $cap   = [Math]::Max($Limit * 20, 50)   # safety valve against infinite loop

    while ($Global:CreatedUsers.Count -lt $goal -and $tries -lt $cap) {
        $tries++
        $firstname = VulnAD-GetRandom -InputList $Global:HumansNames
        $lastname  = VulnAD-GetRandom -InputList $Global:HumansNames
        $SamAccountName = ("{0}.{1}" -f $firstname, $lastname).ToLower()

        if ($Global:CreatedUsers -contains $SamAccountName) { continue }

        $upn = "$SamAccountName@$Global:Domain"
        $pwd = [System.Web.Security.Membership]::GeneratePassword(14, 3)

        try {
            New-ADUser -Name "$firstname $lastname" `
                -GivenName $firstname -Surname $lastname `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $upn `
                -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
                -OtherAttributes @{ comment = $Global:VulnADTag } `
                -Enabled $true -ErrorAction Stop
            $Global:CreatedUsers += $SamAccountName
            Write-Info "Created user: $SamAccountName"
        } catch {
            Write-Bad "Failed to create ${SamAccountName}: $($_.Exception.Message)"
        }
    }

    if ($tries -ge $cap) {
        Write-Warn "  Hit attempt cap ($cap) before reaching target; name pool may be too small."
    }
}

function VulnAD-AddADGroup {
    Param([array]$GroupList)
    foreach ($group in $GroupList) {
        Write-Info "Creating group: $group"
        try { New-ADGroup -Name $group -GroupScope Global -ErrorAction Stop } catch {}

        # Add 3-15 DISTINCT members (previous version could pick the same user repeatedly)
        $memberCount = Get-Random -Minimum 3 -Maximum 16
        if (@($Global:CreatedUsers).Count -gt 0) {
            $take    = [Math]::Min($memberCount, @($Global:CreatedUsers).Count)
            $members = @($Global:CreatedUsers | Get-Random -Count $take)
            try { Add-ADGroupMember -Identity $group -Members $members -ErrorAction SilentlyContinue } catch {}
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

    # Use the account explicitly flagged Weak (svc_mssql) as the crackable one;
    # every other service account gets a long random password.
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
                -OtherAttributes @{ comment = $Global:VulnADTag } `
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
    foreach ($u in (VulnAD-ReserveUsers -Count $count)) {
        $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords
        try {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            Set-ADAccountControl  -Identity $u -DoesNotRequirePreAuth $true
            Write-Info "  [ASREP] $u - DoesNotRequirePreAuth + weak password"
        } catch {
            Write-Bad "  [ASREP] $u : $($_.Exception.Message)"
        }
    }
}

function VulnAD-DnsAdmins {
    Write-Info 'Populating DnsAdmins group with abusable members...'
    $count = Get-Random -Minimum 2 -Maximum 6
    # DnsAdmins only ADDS membership (no password/description mutation), so it
    # may overlap other labs - but pick distinct members within this call.
    if (@($Global:CreatedUsers).Count -gt 0) {
        $take    = [Math]::Min($count, @($Global:CreatedUsers).Count)
        $members = @($Global:CreatedUsers | Get-Random -Count $take)
        foreach ($u in $members) {
            try {
                Add-ADGroupMember -Identity 'DnsAdmins' -Members $u -ErrorAction SilentlyContinue
                Write-Info "  [DnsAdmins] $u"
            } catch {}
        }
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
    foreach ($u in (VulnAD-ReserveUsers -Count $count)) {
        $pwd = [System.Web.Security.Membership]::GeneratePassword(12, 2)
        try {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            $templates = @(
                "User Password $pwd",
                "temp pw: $pwd (do not delete)",
                "Password for onboarding: $pwd",
                "Reset -> $pwd"
            )
            $desc = VulnAD-GetRandom -InputList $templates
            Set-ADUser $u -Description $desc
            Write-Info "  [Description-Password] $u"
        } catch {
            Write-Bad "  [Description-Password] $u : $($_.Exception.Message)"
        }
    }
}

function VulnAD-DefaultPassword {
    Write-Info 'Setting default password on onboarding accounts...'
    $count = Get-Random -Minimum 3 -Maximum 6
    foreach ($u in (VulnAD-ReserveUsers -Count $count)) {
        try {
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString 'Changeme123!' -AsPlainText -Force)
            Set-ADUser $u -Description 'New user - default password' -ChangePasswordAtLogon $true
            Write-Info "  [DefaultPassword] $u"
        } catch {
            Write-Bad "  [DefaultPassword] $u : $($_.Exception.Message)"
        }
    }
}

function VulnAD-PasswordSpraying {
    Write-Info 'Setting shared password across multiple accounts (spray target)...'
    $shared = 'ncc1701'
    $count = Get-Random -Minimum 8 -Maximum 14
    foreach ($u in (VulnAD-ReserveUsers -Count $count)) {
        try {
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString $shared -AsPlainText -Force)
            Set-ADUser $u -Description 'Standard user account'
            Write-Info "  [PasswordSpray] $u <- $shared"
        } catch {
            Write-Bad "  [Spray] $u : $($_.Exception.Message)"
        }
    }
}

function VulnAD-DCSync {
    Write-Info 'Granting DCSync extended rights to random users...'
    $count = Get-Random -Minimum 2 -Maximum 5
    # Grants rights only (no password change). Pick DISTINCT users, and record
    # the marker in 'info' so it does not overwrite planted description secrets.
    if (@($Global:CreatedUsers).Count -eq 0) { return }
    $take    = [Math]::Min($count, @($Global:CreatedUsers).Count)
    $targets = @($Global:CreatedUsers | Get-Random -Count $take)

    foreach ($u in $targets) {
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
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
            }
            $ADObject.psbase.CommitChanges()
            Set-ADUser $u -Replace @{ info = 'Replication Account' }
            Write-Info "  [DCSync] $u - granted 3 replication extended rights"
        } catch {
            Write-Bad "  [DCSync] $u : $($_.Exception.Message)"
        }
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
        Sets TrustedForDelegation on a member server, self-provisioning one
        if the lab has no non-DC computers yet.
    #>
    Write-Info 'Configuring Unconstrained Delegation on a member server...'

    $target = VulnAD-EnsureMemberComputer
    if (-not $target) { return }

    try {
        Set-ADComputer -Identity $target.DistinguishedName -TrustedForDelegation $true
        Write-Info "  [Unconstrained] $($target.Name)"
    } catch {
        Write-Bad "  Failed to set on $($target.Name): $($_.Exception.Message)"
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
            -OtherAttributes @{ comment = $Global:VulnADTag } `
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
            -OtherAttributes @{ comment = $Global:VulnADTag } `
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

    # Grant GenericWrite on up to 5 computer objects to random users.
    # Self-provision a member computer if the lab has none yet.
    try {
        $computers = @(Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Select-Object -First 5)
        if (-not $computers) {
            $c = VulnAD-EnsureMemberComputer
            if ($c) { $computers = @($c) }
        }
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
        $computers = @(Get-ADComputer -Filter { PrimaryGroupID -ne 516 })
        if (-not $computers) {
            $c = VulnAD-EnsureMemberComputer
            if ($c) { $computers = @($c) }
        }
        if (-not $computers) { return }

        $take      = [Math]::Min(2, @($computers).Count)
        $computers = @($computers | Get-Random -Count $take)
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

    # gMSA 2: securely scoped (control group).
    # Self-provision a member computer so this always has a valid principal.
    try {
        $existing = Get-ADServiceAccount -Filter { Name -eq 'gmsa_secure' } -ErrorAction SilentlyContinue
        if (-not $existing) {
            $target = VulnAD-EnsureMemberComputer
            if (-not $target) {
                $target = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } | Select-Object -First 1
            }
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
    foreach ($u in (VulnAD-ReserveUsers -Count $count)) {
        $pwd = [System.Web.Security.Membership]::GeneratePassword(14, 3)
        try {
            # Enable AllowReversiblePasswordEncryption
            Set-ADAccountControl -Identity $u -AllowReversiblePasswordEncryption $true
            # Password must be RESET after enabling the flag so it's stored reversibly
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            Write-Warn "  [ReversibleEnc] $u - cleartext recoverable via secretsdump"
        } catch {
            Write-Bad "  [ReversibleEnc] $u : $($_.Exception.Message)"
        }
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
        # Draw three DISTINCT users up front instead of retrying by chance.
        if (@($Global:CreatedUsers).Count -lt 3) {
            Write-Warn '  Not enough users for a 3-hop chain, skipping'
            return
        }
        $picked = @($Global:CreatedUsers | Get-Random -Count 3)
        $userA, $userB, $userC = $picked

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

    # Domain identity is taken from AD itself (authoritative). -DomainName is
    # only validated so UPNs / SPNs / SYSVOL paths can never point at the wrong domain.
    $actual = Get-ADDomain
    if ($DomainName -and $DomainName -ne $actual.DNSRoot) {
        Write-Warn "Provided -DomainName '$DomainName' does not match actual domain '$($actual.DNSRoot)'."
        Write-Warn "Using the actual domain '$($actual.DNSRoot)' for all operations."
    }
    $Global:Domain        = $actual.DNSRoot
    $Global:DomainDN      = $actual.DistinguishedName
    $Global:DomainSid     = $actual.DomainSID.Value
    $Global:CreatedUsers  = @()
    $Global:ReservedUsers = @()
    $Global:AllObjects    = @()

    Write-Info "Domain: $Global:Domain"
    Write-Info "Domain DN: $Global:DomainDN"
    Write-Info "OS Build: $(VulnAD-GetOSVersion)"

    # The password/description labs draw distinct users from a shared reserve
    # pool (~up to ~35 users total). Below this floor the later labs - the
    # password-spray target in particular - will silently run short of targets.
    $reserveFloor = 40
    if ($UsersLimit -lt $reserveFloor) {
        Write-Warn "UsersLimit=$UsersLimit is low. The reserve pool may be exhausted and later"
        Write-Warn "  labs (e.g. Password Spraying) will get few or no accounts. Recommend >= $reserveFloor."
    }

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
    Write-Good "Created $($Global:CreatedUsers.Count) users"

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
# Cleanup / reset
# ============================================================

function Remove-VulnADExtended {
    <#
    .SYNOPSIS
        Reverse (as far as practical) what Invoke-VulnADExtended created, so the
        lab can be rebuilt from a clean state without stacking duplicate ACEs.

    .DESCRIPTION
        Works without relying on in-memory state: lab users are located by the
        'comment' = VULNAD-EXTENDED marker, everything else by its fixed name.

        Steps:
          1. Collect the SIDs of all lab principals (tagged users + fixed-name
             groups/computers) BEFORE deleting anything.
          2. Purge every Allow ACE granted to those SIDs from the objects that
             SURVIVE deletion (domain root, AdminSDHolder, Domain Admins,
             CN=Computers, and any member computers). ACEs on objects that are
             themselves deleted disappear automatically.
          3. Delete lab users, placeholder computers, gMSAs, the builder's
             groups, and the dMSA OU (recursively).
          4. Remove the planted GPP Groups.xml from SYSVOL.
          5. Optionally re-enable SMB signing.

        NOT reverted (stated plainly rather than done blindly):
          - Domain password policy and ms-DS-MachineAccountQuota: their prior
            values are unknown, so they are left as-is (warned).
          - If SDProp already propagated the AdminSDHolder ACE to protected
            objects (>~60 min after build), those inherited ACEs persist until
            the next SDProp cycle re-templates them. A DC snapshot revert
            remains the only guaranteed full reset.

    .EXAMPLE
        Remove-VulnADExtended -Force
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param(
        [switch]$Force,
        [switch]$ReenableSMBSigning
    )

    if (-not (VulnAD-CheckPrerequisites)) { return }

    if (-not $Force -and -not $PSCmdlet.ShouldProcess('this domain', 'Remove all VulnAD-Extended lab objects')) {
        return
    }

    $actual = Get-ADDomain
    $Global:Domain   = $actual.DNSRoot
    $Global:DomainDN = $actual.DistinguishedName

    Write-Info "Cleaning up VulnAD-Extended objects in $Global:Domain ..."

    # --- 1. Collect lab principals and their SIDs (before deletion) ---
    $labUsers = @()
    try {
        $labUsers = @(Get-ADUser -LDAPFilter "(comment=$Global:VulnADTag)" -ErrorAction SilentlyContinue)
    } catch {}
    # Fixed-name service users, in case a tag write failed
    foreach ($n in $Global:FixedSvcUsers) {
        if ($labUsers.SamAccountName -notcontains $n) {
            try { $labUsers += Get-ADUser -Identity $n -ErrorAction SilentlyContinue } catch {}
        }
    }
    $labUsers = @($labUsers | Where-Object { $_ } | Sort-Object DistinguishedName -Unique)

    $labGroups = @()
    foreach ($g in ($Global:HighGroups + $Global:MidGroups + $Global:NormalGroups)) {
        try { $labGroups += Get-ADGroup -Identity $g -ErrorAction SilentlyContinue } catch {}
    }
    $labGroups = @($labGroups | Where-Object { $_ })

    $labComputers = @()
    foreach ($c in $Global:FixedComputers) {
        try { $labComputers += Get-ADComputer -Identity $c -ErrorAction SilentlyContinue } catch {}
    }
    $labComputers = @($labComputers | Where-Object { $_ })

    # SID set used for ACE purge
    $labSids = @()
    foreach ($p in ($labUsers + $labGroups + $labComputers)) {
        if ($p.SID) { $labSids += $p.SID.Value }
    }
    $labSids = @($labSids | Sort-Object -Unique)
    Write-Info "  Found $($labUsers.Count) users, $($labGroups.Count) groups, $($labComputers.Count) computers to remove"

    # --- 2. Purge ACEs granted to lab SIDs from surviving objects ---
    $purgeTargets = @(
        $Global:DomainDN,
        "CN=AdminSDHolder,CN=System,$Global:DomainDN",
        "CN=Computers,$Global:DomainDN"
    )
    try { $purgeTargets += (Get-ADGroup -Identity 'Domain Admins').DistinguishedName } catch {}
    # Any real member computers that may carry RBCD/ShadowCred ACEs
    try {
        $purgeTargets += (Get-ADComputer -Filter { PrimaryGroupID -ne 516 } -ErrorAction SilentlyContinue |
                          ForEach-Object { $_.DistinguishedName })
    } catch {}
    $purgeTargets = @($purgeTargets | Where-Object { $_ } | Sort-Object -Unique)

    foreach ($t in $purgeTargets) {
        try {
            $o = [ADSI]("LDAP://$t")
            $changed = $false
            foreach ($sidStr in $labSids) {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                    $o.psbase.ObjectSecurity.PurgeAccessRules($sid)   # removes all ACEs for this SID; no-op if none
                    $changed = $true
                } catch {}
            }
            if ($changed) { $o.psbase.CommitChanges() }
        } catch {
            Write-Bad "  ACE purge failed on ${t}: $($_.Exception.Message)"
        }
    }
    Write-Info '  Purged lab ACEs from surviving objects (domain root, AdminSDHolder, Domain Admins, computers container)'

    # --- 3. Delete lab objects (leaves first) ---
    foreach ($u in $labUsers) {
        try { Remove-ADUser -Identity $u.DistinguishedName -Confirm:$false -ErrorAction Stop; Write-Info "  [del] user $($u.SamAccountName)" }
        catch { Write-Bad "  del user $($u.SamAccountName): $($_.Exception.Message)" }
    }

    foreach ($c in $labComputers) {
        try {
            Set-ADObject -Identity $c.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
            Remove-ADComputer -Identity $c.DistinguishedName -Confirm:$false -ErrorAction Stop
            Write-Info "  [del] computer $($c.Name)"
        } catch { Write-Bad "  del computer $($c.Name): $($_.Exception.Message)" }
    }

    foreach ($m in $Global:FixedGMSAs) {
        try {
            $sa = Get-ADServiceAccount -Identity $m -ErrorAction SilentlyContinue
            if ($sa) { Remove-ADServiceAccount -Identity $m -Confirm:$false -ErrorAction Stop; Write-Info "  [del] gMSA $m" }
        } catch { Write-Bad "  del gMSA ${m}: $($_.Exception.Message)" }
    }

    foreach ($g in $labGroups) {
        try { Remove-ADGroup -Identity $g.DistinguishedName -Confirm:$false -ErrorAction Stop; Write-Info "  [del] group $($g.Name)" }
        catch { Write-Bad "  del group $($g.Name): $($_.Exception.Message)" }
    }

    foreach ($ouName in $Global:FixedOUs) {
        $ouPath = "OU=$ouName,$Global:DomainDN"
        try {
            $ou = Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction SilentlyContinue
            if ($ou) {
                Set-ADObject -Identity $ouPath -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
                Remove-ADOrganizationalUnit -Identity $ouPath -Recursive -Confirm:$false -ErrorAction Stop
                Write-Info "  [del] OU $ouName"
            }
        } catch { Write-Bad "  del OU ${ouName}: $($_.Exception.Message)" }
    }

    # --- 4. Remove planted GPP Groups.xml ---
    try {
        $policies = "\\$Global:Domain\SYSVOL\$Global:Domain\Policies"
        if (Test-Path $policies) {
            Get-ChildItem $policies -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $groupsXml = Join-Path $_.FullName 'Machine\Preferences\Groups\Groups.xml'
                if (Test-Path $groupsXml) {
                    $content = Get-Content $groupsXml -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'LocalAdmin' -and $content -match 'cpassword') {
                        Remove-Item $groupsXml -Force -ErrorAction SilentlyContinue
                        Write-Info "  [del] planted GPP Groups.xml in $($_.Name)"
                    }
                }
            }
        }
    } catch { Write-Bad "  GPP cleanup: $($_.Exception.Message)" }

    # --- 5. Optional: re-enable SMB signing ---
    if ($ReenableSMBSigning) {
        try {
            Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -Force
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -Force
            Write-Info '  Re-enabled SMB signing'
        } catch { Write-Bad "  SMB signing: $($_.Exception.Message)" }
    }

    Write-Host ''
    Write-Good 'VulnAD-Extended cleanup complete'
    Write-Warn 'NOT reverted automatically:'
    Write-Warn '  - Domain password policy and ms-DS-MachineAccountQuota (prior values unknown)'
    Write-Warn '  - Any AdminSDHolder ACE already propagated by SDProp to protected objects'
    Write-Warn '  For a guaranteed clean baseline, revert the DC snapshot instead.'
}

# ============================================================
# Module export
# ============================================================

Export-ModuleMember -Function Invoke-VulnADExtended, Remove-VulnADExtended -ErrorAction SilentlyContinue
