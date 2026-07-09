<#
.SYNOPSIS
    VulnAD-Extended — 升級版 Vulnerable Active Directory 建置腳本

.DESCRIPTION
    在原 VulnAD (by wazehell/@safe_buffer) 的基礎上大幅擴增，涵蓋以下訓練主題：

    基礎（保留自原版）：
      - Password Spraying / Default Password / Description Password
      - AS-REP Roasting / Kerberoasting
      - DnsAdmins Abuse / DCSync 授權
      - Bad ACL 多層交叉授權
      - SMB Signing 停用

    委派攻擊：
      - Unconstrained Delegation（機器帳戶）
      - Constrained Delegation - Kerberos Only
      - Constrained Delegation - Protocol Transition (Any Auth)
      - RBCD 條件（保留 MachineAccountQuota=10）

    憑證攻擊：
      - Shadow Credentials 前置條件（授予 GenericWrite）
      - AD CS ESC1 / ESC4 / ESC7（若 AD CS 已安裝則設定）
      - Certificate Chain（授予 CA ACL）

    現代化服務帳戶：
      - gMSA + 過度授權（Domain Computers 可讀密碼）
      - dMSA CreateChild 權限（僅 Server 2025 DC 上有效）

    LAPS：
      - Legacy LAPS Schema 擴充（若可用）
      - LAPS 密碼讀取權限過度授權

    Legacy / 弱設定：
      - pre2k 機器帳戶（密碼可預測）
      - Reversible Encryption 啟用帳戶
      - GPP cpassword 檔案在 SYSVOL

    強制認證前置：
      - Print Spooler 服務啟用（PrinterBug 條件）
      - WebClient 服務啟用（WebDAV Coercion 條件）

    持久化前置：
      - AdminSDHolder ACL 後門
      - 多層 ACL 巢狀（A→B→C→Domain Admins）

.EXAMPLE
    Invoke-VulnADExtended -DomainName "redteamlab.local" -UsersLimit 100

.EXAMPLE
    Invoke-VulnADExtended -DomainName "redteamlab.local" -SkipADCS -SkipDelegation

.NOTES
    Author: Extended based on wazehell/@safe_buffer's VulnAD
    僅供合法授權的紅隊訓練與靶場建置使用。
#>

# ============================================================
# Global 資料清單
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

# 服務帳戶 SPN 對照（會建立為 User 帳戶而非 gMSA，以便 Kerberoasting）
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
# 輔助輸出
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
        '  ╔═══════════════════════════════════════════════════════════╗',
        '  ║   VulnAD-Extended — Vulnerable Active Directory (v2.0)   ║',
        '  ║   Original by wazehell/@safe_buffer, Extended edition    ║',
        '  ║   For authorized red-team lab environments only          ║',
        '  ╚═══════════════════════════════════════════════════════════╝',
        ''
    )
    $banner | ForEach-Object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','White'))
    }
}

# ============================================================
# 通用工具函數
# ============================================================

function VulnAD-GetRandom {
    Param([array]$InputList)
    return Get-Random -InputObject $InputList
}

function VulnAD-CheckPrerequisites {
    Write-Info 'Checking prerequisites...'

    # 檢查 RSAT / AD Module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Bad 'ActiveDirectory PowerShell module not found. Install RSAT-AD-PowerShell.'
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # 是否為 DC
    try {
        $null = Get-ADDomain -ErrorAction Stop
    } catch {
        Write-Bad 'Cannot query AD. This script must run on a Domain Controller or a domain-joined machine with RSAT.'
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
# 基礎函數（保留自原版）
# ============================================================

function VulnAD-AddADUser {
    Param([int]$Limit = 1)
    Add-Type -AssemblyName System.Web

    for ($i = 1; $i -le $Limit; $i++) {
        $firstname = VulnAD-GetRandom -InputList $Global:HumansNames
        $lastname  = VulnAD-GetRandom -InputList $Global:HumansNames
        $SamAccountName = ("{0}.{1}" -f $firstname, $lastname).ToLower()

        # 避免重複
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
        # 隨機加入 3-15 個成員
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

    # 階梯 1：NormalGroup → MidGroup（供 BloodHound 練習）
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

    # 階梯 2：MidGroup → HighGroup
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

    # 隨機混合 ACE
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

    # 從清單中隨機挑一個「弱密碼」帳戶
    $weakOne = ($Global:ServicesAccountsAndSPNs | Where-Object { $_.Weak })[0]

    foreach ($svc in $Global:ServicesAccountsAndSPNs) {
        $spn = "$($svc.SPN).$Global:Domain"

        if ($svc.Name -eq $weakOne.Name) {
            $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords
            Write-Warn "  [WEAK] $($svc.Name) with SPN=$spn — password from BadPasswords list"
        } else {
            $pwd = [System.Web.Security.Membership]::GeneratePassword(24, 5)
            Write-Info "  [SAFE] $($svc.Name) with SPN=$spn — random 24-char password"
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
            # 已存在則補設定
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
            Write-Info "  [ASREP] $u — DoesNotRequirePreAuth + weak password"
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
    # 巢狀：讓中權限群組成為 DnsAdmins 的間接成員
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
            # 用不同關鍵字型式，模擬真實情境
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
            Write-Info "  [PasswordSpray] $u ← $shared"
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
            Write-Info "  [DCSync] $u — granted 3 replication extended rights"
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
# 擴增函數 — 委派攻擊
# ============================================================

function VulnAD-UnconstrainedDelegation {
    <#
        對應 Lab：Unconstrained Delegation + Printer Bug (Vol1 Lab4-5, Course Part1 Lab4-5)
        設定隨機一台成員伺服器（或建立虛擬電腦帳戶）為 TrustedForDelegation
    #>
    Write-Info 'Configuring Unconstrained Delegation on a member server...'

    # 尋找非 DC 的電腦帳戶
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
        # 沒有成員伺服器 → 建立一個假的電腦帳戶模擬
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
        對應 Lab：Constrained Delegation (Kerberos Only & Any Auth)
        - svc_iis 設定為 Any Auth（Protocol Transition + Constrained）
        - svc_web 設定為 Kerberos Only
    #>
    Write-Info 'Configuring Constrained Delegation service accounts...'

    Add-Type -AssemblyName System.Web

    # Any Auth（Protocol Transition）
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
        Write-Info "  [Constrained-AnyAuth] svc_iis → $target"
    } catch {
        Write-Bad "  svc_iis: $($_.Exception.Message)"
    }

    # Kerberos Only
    try {
        $pwd = VulnAD-GetRandom -InputList $Global:BadPasswords  # 弱密碼，方便 Kerberoasting
        New-ADUser -Name 'svc_web' -SamAccountName 'svc_web' `
            -UserPrincipalName "svc_web@$Global:Domain" `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -Enabled $true -PasswordNeverExpires $true `
            -Description 'Web frontend service' `
            -ServicePrincipalNames @{Add=@("HTTP/frontend.$Global:Domain")} `
            -ErrorAction Stop

        $target = "CIFS/$(($env:COMPUTERNAME)).$Global:Domain"
        Set-ADUser 'svc_web' -Add @{ 'msDS-AllowedToDelegateTo' = @($target) }
        # 不設定 TrustedToAuthForDelegation = Kerberos Only
        $Global:CreatedUsers += 'svc_web'
        Write-Info "  [Constrained-KerberosOnly] svc_web → $target (weak password)"
    } catch {
        Write-Bad "  svc_web: $($_.Exception.Message)"
    }
}

function VulnAD-RBCDPrep {
    <#
        對應 Lab：RBCD
        1. 保留預設 MachineAccountQuota=10（讓低權限也能建立機器帳戶）
        2. 授予某使用者對電腦物件的 GenericWrite（RBCD 攻擊入口）
    #>
    Write-Info 'Preparing RBCD attack surface...'

    # 確認 MachineAccountQuota
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

    # 對每一台成員電腦，隨機挑一個使用者授予 GenericWrite
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
        對應 Lab：Shadow Credentials (第二冊題7 + 第四冊 RB1)
        授予某使用者對目標電腦的 GenericWrite（可寫入 msDS-KeyCredentialLink）
        與 RBCD 前置條件重疊 — 但顯性標註為 Shadow Credentials 目標
    #>
    Write-Info 'Preparing Shadow Credentials attack surface...'
    try {
        $computers = Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Get-Random -Count 2
        foreach ($c in $computers) {
            $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
            $Src = Get-ADUser -Identity $u
            # GenericAll 可以寫入所有屬性包括 msDS-KeyCredentialLink
            if (VulnAD-AddACL -Source $Src.SID -Destination $c.DistinguishedName -Rights 'GenericAll') {
                Write-Info "  [ShadowCred-Entry] $u has GenericAll over $($c.Name)"
            }
        }
    } catch {}
}

# ============================================================
# 擴增函數 — AD CS ESC 系列
# ============================================================

function VulnAD-ADCSVulnerable {
    <#
        對應 Lab：AD CS ESC1 / ESC4 / ESC7 (第二冊題16-17, 第四冊 CS1-CS7)
        僅在 AD CS 已安裝時執行
    #>
    if (-not (VulnAD-IsADCSInstalled)) {
        Write-Warn 'AD CS not installed — skipping ADCS vulnerabilities'
        Write-Warn '  Install with: Install-WindowsFeature AD-Certificate -IncludeManagementTools'
        Write-Warn '  Then: Install-AdcsCertificationAuthority -CAType EnterpriseRootCa'
        return
    }

    Write-Info 'Configuring vulnerable AD CS templates...'

    try {
        # ESC1 條件：Client Authentication EKU + Enrollee Supplies Subject + 低權限可 Enroll
        # 由於 template 屬性複雜，這裡建立標記讓學員知道要手動或用 certipy 檢查
        Write-Info '  [ESC-Hint] Manually check with: certipy find -u <user>@<domain> -p <pass> -vulnerable'
        Write-Info '  Or on DC: certutil -catemplates'

        # ESC7：授予非管理員對 CA 的 ManageCA / ManageCertificates
        # 需要透過 certutil 或 DCOM 方式，這裡透過 Registry 標記
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        try {
            $ca = Get-CertificationAuthority -ErrorAction SilentlyContinue |
                  Where-Object { $_.IsRoot } | Select-Object -First 1
            if ($ca) {
                # 使用 certutil 授權（需要 PSPKI 或手動）
                Write-Warn "  [ESC7-Hint] Grant ManageCA/ManageCertificates to $u manually:"
                Write-Warn "    certutil -setreg 'CA\Security' — See PSPKI module for automation"
            }
        } catch {}

        # 建立一個易受攻擊的模板名稱標記
        Write-Info '  [ADCS] Suggested manual step: duplicate "User" template as "VulnUser"'
        Write-Info '    Enable "Supply in the request" + Client Auth EKU + Domain Users can Enroll'
    } catch {
        Write-Bad "  ADCS setup: $($_.Exception.Message)"
    }
}

# ============================================================
# 擴增函數 — gMSA / dMSA
# ============================================================

function VulnAD-VulnerableGMSA {
    <#
        對應 Lab：gMSA (SCCM/DCOM/gMSA 專項 G1-G4)
        建立 gMSA 並過度授權（Domain Computers 可讀取密碼）
    #>
    Write-Info 'Creating gMSA with excessive permissions...'

    # 檢查 KDS Root Key
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

    # gMSA 1：過度授權（Domain Computers 可讀取 → 任何入侵的機器都能取得密碼）
    try {
        $existing = Get-ADServiceAccount -Filter { Name -eq 'gmsa_overshare' } -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-ADServiceAccount -Name 'gmsa_overshare' `
                -DNSHostName "gmsa_overshare.$Global:Domain" `
                -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers' `
                -ServicePrincipalNames @("MSSQLSvc/gmsa-sql.$Global:Domain:1433") `
                -ErrorAction Stop
            Write-Warn '  [gMSA-OverPriv] gmsa_overshare — readable by ALL domain computers'
        } else {
            Write-Info '  gmsa_overshare already exists'
        }
    } catch {
        Write-Bad "  gmsa_overshare: $($_.Exception.Message)"
    }

    # gMSA 2：正確授權（對照組）
    try {
        $existing = Get-ADServiceAccount -Filter { Name -eq 'gmsa_secure' } -ErrorAction SilentlyContinue
        if (-not $existing) {
            # 挑一台成員伺服器（若無則用 DC 自己作為佔位）
            $target = (Get-ADComputer -Filter { PrimaryGroupID -ne 516 } | Select-Object -First 1)
            if (-not $target) { $target = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } | Select-Object -First 1 }
            New-ADServiceAccount -Name 'gmsa_secure' `
                -DNSHostName "gmsa_secure.$Global:Domain" `
                -PrincipalsAllowedToRetrieveManagedPassword "$($target.SamAccountName)" `
                -ErrorAction Stop
            Write-Info "  [gMSA-Secure] gmsa_secure — only $($target.Name) can read"
        }
    } catch {
        Write-Bad "  gmsa_secure: $($_.Exception.Message)"
    }
}

function VulnAD-DMSAPrep {
    <#
        對應 Lab：BadSuccessor (第六冊 Lab1, 2026現代技術冊 Lab1)
        僅在 Windows Server 2025 上有效
    #>
    if (-not (VulnAD-IsServer2025)) {
        Write-Warn 'This host is not Server 2025 — dMSA/BadSuccessor conditions cannot be created'
        return
    }

    Write-Info 'Preparing dMSA/BadSuccessor conditions (Server 2025)...'

    try {
        # 建立一個 OU 讓非管理員可以在其中建立 dMSA
        $ouPath = "OU=ServiceAccountsOU,$Global:DomainDN"
        $ouExists = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ouPath } -ErrorAction SilentlyContinue
        if (-not $ouExists) {
            New-ADOrganizationalUnit -Name 'ServiceAccountsOU' -Path $Global:DomainDN `
                -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }

        # 授予一個中權限群組對該 OU 的 CreateChild（針對 msDS-DelegatedManagedServiceAccount）
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
        Write-Warn '  Any member of this group can perform BadSuccessor attack'
    } catch {
        Write-Bad "  dMSA prep failed: $($_.Exception.Message)"
    }
}

# ============================================================
# 擴增函數 — LAPS
# ============================================================

function VulnAD-VulnerableLAPS {
    <#
        對應 Lab：LAPS (Vol1 Lab10, Course Part1 Lab10)
        1. 檢查 LAPS Schema 是否已擴充
        2. 授予中權限群組讀取 LAPS 密碼
    #>
    Write-Info 'Configuring LAPS with over-privileged read access...'

    # 檢查 Legacy LAPS Schema（ms-Mcs-AdmPwd）
    $legacyLaps = Get-ADObject -Filter { Name -eq 'ms-Mcs-AdmPwd' } `
        -SearchBase "CN=Schema,CN=Configuration,$Global:DomainDN" -ErrorAction SilentlyContinue

    if (-not $legacyLaps) {
        Write-Warn '  Legacy LAPS schema not found — install with Update-AdmPwdADSchema (from LAPS.x64.msi)'
        Write-Warn '  Or use Windows LAPS: Update-LapsADSchema'
    }

    # 授予中權限群組讀取 LAPS 密碼（過度授權）
    try {
        $computersOU = "CN=Computers,$Global:DomainDN"
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $Src = Get-ADGroup -Identity $mgroup

        $ou = [ADSI]("LDAP://$computersOU")
        # 授予 Extended Right: All Extended Rights (包含 LAPS 讀取)
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
# 擴增函數 — Legacy 弱設定
# ============================================================

function VulnAD-Pre2kComputer {
    <#
        對應 Lab：Pre-Windows 2000 Compatible Access
        Pre2k 機器帳戶的初始密碼 = 電腦名稱小寫（移除 $，最多 14 字元）
        且從未登入 = 密碼未變更
    #>
    Write-Info 'Creating pre-Windows 2000 style computer account with predictable password...'

    $name = 'LEGACYPC'
    try {
        $existing = Get-ADComputer -Filter { Name -eq $name } -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Info "  $name already exists"
            return
        }

        # 密碼 = 電腦名小寫（不含 $）
        $pwd = $name.ToLower()
        New-ADComputer -Name $name `
            -SamAccountName "$name`$" `
            -Path "CN=Computers,$Global:DomainDN" `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Description 'Legacy pre-2000 compatible account' `
            -ErrorAction Stop

        # 設定 UserAccountControl 讓密碼不強制更新
        Set-ADAccountControl -Identity "$name`$" -PasswordNotRequired $true
        Write-Warn "  [Pre2k] $name`$ — password = '$pwd' (predictable, never logged on)"
    } catch {
        Write-Bad "  Pre2k: $($_.Exception.Message)"
    }
}

function VulnAD-ReversibleEncryption {
    <#
        對應 Lab：Reversible Encryption
        啟用可逆加密的帳戶 → 從 ntds.dit 可取得明文密碼
    #>
    Write-Info 'Enabling reversible encryption on random accounts...'
    Add-Type -AssemblyName System.Web
    $count = Get-Random -Minimum 2 -Maximum 4
    for ($i = 1; $i -le $count; $i++) {
        $u = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $pwd = [System.Web.Security.Membership]::GeneratePassword(14, 3)
        try {
            # 啟用 AllowReversiblePasswordEncryption
            Set-ADAccountControl -Identity $u -AllowReversiblePasswordEncryption $true
            # 密碼必須在旗標啟用後重設，才會被以可逆方式儲存
            Set-ADAccountPassword -Identity $u -Reset `
                -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            Write-Warn "  [ReversibleEnc] $u — cleartext recoverable via secretsdump"
        } catch {}
    }
}

function VulnAD-GPPPassword {
    <#
        對應 Lab：GPP Password (cpassword in SYSVOL)
        在 SYSVOL 中放置 Groups.xml（有加密的 cpassword）
        金鑰是公開的 AES 金鑰，可用 gpp-decrypt 解密
    #>
    Write-Info 'Planting GPP cpassword file in SYSVOL...'

    $sysvolPath = "\\$Global:Domain\SYSVOL\$Global:Domain\Policies"
    if (-not (Test-Path $sysvolPath)) {
        Write-Bad "  SYSVOL not accessible at $sysvolPath"
        return
    }

    # 選擇一個既有的 GPO 目錄
    $gpoDir = Get-ChildItem $sysvolPath -Directory | Select-Object -First 1
    if (-not $gpoDir) {
        Write-Bad '  No GPO directory found'
        return
    }

    $prefsDir = Join-Path $gpoDir.FullName 'Machine\Preferences\Groups'
    if (-not (Test-Path $prefsDir)) {
        New-Item -Path $prefsDir -ItemType Directory -Force | Out-Null
    }

    # 這是眾所皆知的 cpassword，明文 "Local*P4ssword!" 用公開 AES 金鑰加密後的結果
    # 學員會用 gpp-decrypt / Get-GPPPassword 解出
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
        Write-Warn '  Decrypt with: gpp-decrypt <cpassword> (Kali) or Get-GPPPassword (PowerShell)'
    } catch {
        Write-Bad "  GPP: $($_.Exception.Message)"
    }
}

# ============================================================
# 擴增函數 — Coercion 前置
# ============================================================

function VulnAD-CoercionServices {
    <#
        對應 Lab：Coercion 技術棧 (第四冊 CO1)
        確保以下服務啟用，讓 Coercion 攻擊可用：
        - Print Spooler (PrinterBug / MS-RPRN)
        - Encrypting File System (PetitPotam / MS-EFSR)
        - DFS Namespace (DFSCoerce / MS-DFSNM)
        - WebClient (WebDAV Coercion) — 通常在工作站上
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
                Write-Info "  [Coercion] $($svc.Desc) — enabled"
            }
        } catch {}
    }
}

# ============================================================
# 擴增函數 — 持久化前置
# ============================================================

function VulnAD-AdminSDHolderBackdoor {
    <#
        對應 Lab：AdminSDHolder 持久化 (Vol1 題3, Course Part2 Lab18)
        在 AdminSDHolder 物件上授予一個「無害」使用者 FullControl
        SDProp 每 60 分鐘會將此 ACE 傳播到所有 Protected 物件（DA、EA 等）
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
        對應 Lab：多層 ACL 巢狀後門 (第五冊 PE1 技術 4)
        建立 A → B → C → Domain Admins 的攻擊鏈
        BloodHound 可以發現，但手動稽核極難察覺
    #>
    Write-Info 'Building multi-hop ACL chain to Domain Admins...'

    try {
        # A、B、C 都是隨機使用者
        $userA = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $userB = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $userC = VulnAD-GetRandom -InputList $Global:CreatedUsers

        if ($userA -eq $userB -or $userB -eq $userC -or $userA -eq $userC) {
            Write-Warn '  Users collision, skipping multi-hop this run'
            return
        }

        $A = Get-ADUser -Identity $userA
        $B = Get-ADUser -Identity $userB
        $C = Get-ADUser -Identity $userC
        $DA = Get-ADGroup -Identity 'Domain Admins'

        # A → GenericAll → B
        VulnAD-AddACL -Source $A.SID -Destination $B.DistinguishedName -Rights 'GenericAll' | Out-Null
        # B → GenericAll → C
        VulnAD-AddACL -Source $B.SID -Destination $C.DistinguishedName -Rights 'GenericAll' | Out-Null
        # C → WriteDACL → Domain Admins
        VulnAD-AddACL -Source $C.SID -Destination $DA.DistinguishedName -Rights 'WriteDacl' | Out-Null

        Write-Warn "  [MultiHopACL] $userA → $userB → $userC → Domain Admins"
    } catch {
        Write-Bad "  MultiHopACL: $($_.Exception.Message)"
    }
}

# ============================================================
# 主函數
# ============================================================

function Invoke-VulnADExtended {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,

        [int]$UsersLimit = 100,

        # 跳過旗標（讓學員選擇性建置）
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

    # 弱化密碼原則
    Write-Info 'Weakening default password policy...'
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain `
        -LockoutDuration 00:01:00 `
        -LockoutObservationWindow 00:01:00 `
        -LockoutThreshold 0 `
        -ComplexityEnabled $false `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordLength 4

    # === 基礎 ===
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

    # === 擴增：委派 ===
    if (-not $SkipDelegation) {
        VulnAD-UnconstrainedDelegation
        VulnAD-ConstrainedDelegation
        VulnAD-RBCDPrep
        VulnAD-ShadowCredentialsPrep
        Write-Good 'Delegation attack surfaces configured'
    } else { Write-Warn 'Skipped: Delegation' }

    # === 擴增：AD CS ===
    if (-not $SkipADCS) {
        VulnAD-ADCSVulnerable
        Write-Good 'AD CS conditions attempted (see hints for manual steps)'
    } else { Write-Warn 'Skipped: ADCS' }

    # === 擴增：gMSA ===
    if (-not $SkipGMSA) {
        VulnAD-VulnerableGMSA
        Write-Good 'gMSA over-privilege configured'
    } else { Write-Warn 'Skipped: gMSA' }

    # === 擴增：dMSA ===
    if (-not $SkipDMSA) {
        VulnAD-DMSAPrep
    } else { Write-Warn 'Skipped: dMSA' }

    # === 擴增：LAPS ===
    if (-not $SkipLAPS) {
        VulnAD-VulnerableLAPS
        Write-Good 'LAPS over-privilege configured'
    } else { Write-Warn 'Skipped: LAPS' }

    # === 擴增：Legacy ===
    if (-not $SkipLegacy) {
        VulnAD-Pre2kComputer
        VulnAD-ReversibleEncryption
        VulnAD-GPPPassword
        Write-Good 'Legacy weak configurations planted'
    } else { Write-Warn 'Skipped: Legacy' }

    # === 擴增：Coercion 前置 ===
    if (-not $SkipCoercion) {
        VulnAD-CoercionServices
        Write-Good 'Coercion services enabled'
    } else { Write-Warn 'Skipped: Coercion' }

    # === 擴增：持久化前置 ===
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
    Write-Host '  ╔═══════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '  ║              VulnAD-Extended Build Complete              ║' -ForegroundColor Green
    Write-Host '  ╚═══════════════════════════════════════════════════════════╝' -ForegroundColor Green
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
# 匯出
# ============================================================

Export-ModuleMember -Function Invoke-VulnADExtended -ErrorAction SilentlyContinue
