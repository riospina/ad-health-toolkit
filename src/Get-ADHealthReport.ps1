<#
.SYNOPSIS
    AD-Health-Toolkit - Auditoría Integral de Seguridad y Salud de Active Directory
.DESCRIPTION
    Herramienta open-source de diagnóstico automatizado para Active Directory.
    Evalúa:
      - Seguridad de la cuenta krbtgt (Riesgo Golden Ticket / Antigüedad de rotación)
      - Cobertura de Windows LAPS en estaciones y servidores
      - Cuentas de servicio convencionales con SPN (Riesgo de Kerberoasting / migración a gMSA)
      - Matriz de ciclo de vida y End-of-Life (EOL) de Domain Controllers
      - Autoridades de certificación corporativas (AD CS / PKI mediante certutil)
      - Cuentas inactivas habilitadas y Domain Admins en riesgo
      - Contraseñas que nunca expiran y Papelera de Reciclaje de AD
    Genera un informe interactivo HTML ejecutivo con puntuación de salud (0-100).
    100% de Solo Lectura: No realiza cambios ni escrituras en el dominio.

.PARAMETER DaysInactive
    Número de días de inactividad para clasificar cuentas obsoletas (por defecto: 90).

.PARAMETER OutputPath
    Ruta del archivo HTML de reporte a generar.

.PARAMETER Demo
    Modo demostración: Genera datos realistas de prueba para previsualizar el reporte
    sin requerir conexión a un Domain Controller en vivo.

.EXAMPLE
    .\Get-ADHealthReport.ps1 -DaysInactive 60

.EXAMPLE
    .\Get-ADHealthReport.ps1 -Demo

.AUTHOR
    Ing. Ricardo Ospina Franco
    Email: rof.ospina@gmail.com | WhatsApp: +57 318 375 8111
    LinkedIn: https://www.linkedin.com/in/ricardo-ospina-f/
#>

[CmdletBinding()]
param (
    [int]$DaysInactive = 90,
    [string]$OutputPath = "",
    [switch]$Demo
)

$ErrorActionPreference = "SilentlyContinue"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$templatePath = Join-Path $scriptDir "..\templates\report_template.html"

if (-not (Test-Path $templatePath)) {
    Write-Error "No se encontro la plantilla en: $templatePath"
    return
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportsDir = Join-Path $scriptDir "..\reports"
    if (-not (Test-Path $reportsDir)) {
        New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path $reportsDir "AD_Health_Report_$timestamp.html"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AD-Health-Toolkit v1.1.0 | Auditoria de Active Directory" -ForegroundColor White
Write-Host " Autor: Ing. Ricardo Ospina Franco (rof.ospina@gmail.com)" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

function Get-EolInfo([string]$osString) {
    $eol = "Desconocido"
    $status = "Normal"
    $isEol = $false

    if ($osString -match "2008") {
        $eol = "14/01/2020"
        $status = "Vencido / Sin Soporte"
        $isEol = $true
    } elseif ($osString -match "2012") {
        $eol = "10/10/2023"
        $status = "Vencido / Sin Soporte"
        $isEol = $true
    } elseif ($osString -match "2016") {
        $eol = "12/01/2027"
        $status = "Soporte Extendido (Planear Migracion)"
        $isEol = $false
    } elseif ($osString -match "2019") {
        $eol = "09/01/2029"
        $status = "Soporte Extendido"
        $isEol = $false
    } elseif ($osString -match "2022") {
        $eol = "14/10/2031"
        $status = "Soporte Vigente (Saludable)"
        $isEol = $false
    } elseif ($osString -match "2025") {
        $eol = "10/10/2034"
        $status = "Soporte Vigente"
        $isEol = $false
    } else {
        $eol = "Consultar Microsoft Lifecycle"
        $status = "Revision Requerida"
    }

    return @{
        EolDate = $eol
        Status  = $status
        IsEol   = $isEol
    }
}

$domainName = "DESCONOCIDO"
$functionalLevel = "No detectado"
$recycleBinStatus = "Deshabilitada o No Detectada"
$totalUsers = 0
$totalComputers = 0
$inactiveUsers = @()
$pwdNeverExpires = @()
$domainAdmins = @()
$totalLapsEnabled = 0
$totalNonLaps = 0
$domainControllers = @()
$spnUsers = @()
$certAuthorities = @()
$krbtgtInfo = $null

if ($Demo) {
    Write-Host "[i] Modo DEMO activado. Generando infraestructura corporativa simulada..." -ForegroundColor Yellow
    $domainName = "CORP.EMPRESA.LOCAL"
    $functionalLevel = "Windows Server 2016"
    $recycleBinStatus = "Habilitada (Proteccion activa ante borrados)"
    $totalUsers = 640
    $totalComputers = 480
    
    # krbtgt Demo
    $krbtgtDate = (Get-Date).AddDays(-485)
    $krbtgtDays = 485
    $krbtgtInfo = [PSCustomObject]@{
        Account        = "krbtgt"
        PasswordLastSet = $krbtgtDate
        Days           = $krbtgtDays
        Risk           = "CRITICO (>180 dias sin rotacion)"
        Action         = "Ejecutar doble rotacion coordinada con intervalo de replicacion"
    }

    # Usuarios inactivos
    $inactiveUsers = @(
        [PSCustomObject]@{ SamAccountName="carlos.mendoza"; Name="Carlos Mendoza"; LastLogonDate=(Get-Date).AddDays(-142); Enabled=$true; Title="Auxiliar Operativo" },
        [PSCustomObject]@{ SamAccountName="laura.gomez"; Name="Laura Gomez"; LastLogonDate=(Get-Date).AddDays(-210); Enabled=$true; Title="Analista Financiero" },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; LastLogonDate=(Get-Date).AddDays(-320); Enabled=$true; Title="Contratista Externo" },
        [PSCustomObject]@{ SamAccountName="juan.perez"; Name="Juan Perez"; LastLogonDate=(Get-Date).AddDays(-115); Enabled=$true; Title="Soporte Tecnico" },
        [PSCustomObject]@{ SamAccountName="andrea.ruiz"; Name="Andrea Ruiz"; LastLogonDate=(Get-Date).AddDays(-98); Enabled=$true; Title="Coordinadora Comercial" }
    )
    
    # Contraseñas nunca expiran
    $pwdNeverExpires = @(
        [PSCustomObject]@{ SamAccountName="servicio.backup"; Name="Cuenta Servicio Backup"; PasswordLastSet=(Get-Date).AddDays(-410); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; PasswordLastSet=(Get-Date).AddDays(-320); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="gerencia.general"; Name="Gerente General"; PasswordLastSet=(Get-Date).AddDays(-530); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="impresora.scanner"; Name="Scanner Corporativo"; PasswordLastSet=(Get-Date).AddDays(-600); Enabled=$true }
    )
    
    # Domain Admins
    $domainAdmins = @(
        [PSCustomObject]@{ SamAccountName="Administrator"; Name="Administrador Nativo"; LastLogon=(Get-Date).AddDays(-2); Status="Activo" },
        [PSCustomObject]@{ SamAccountName="admin.soporte"; Name="Admin Soporte TI"; LastLogon=(Get-Date).AddDays(-1); Status="Activo" },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; LastLogon=(Get-Date).AddDays(-320); Status="ALERTA: Inactivo" },
        [PSCustomObject]@{ SamAccountName="carlos.mendoza"; Name="Carlos Mendoza (Ex-colaborador)"; LastLogon=(Get-Date).AddDays(-142); Status="ALERTA: Inactivo" }
    )
    
    # LAPS
    $totalLapsEnabled = 42
    $totalNonLaps = 438
    
    # Domain Controllers con evaluacion de ciclo de vida
    $domainControllers = @(
        [PSCustomObject]@{ Name="DC01-MED"; IP="192.168.10.10"; OS="Windows Server 2022 Datacenter"; EolDate="14/10/2031"; Status="Soporte Vigente (Saludable)"; IsEol=$false },
        [PSCustomObject]@{ Name="DC02-BOG"; IP="192.168.20.10"; OS="Windows Server 2019 Standard"; EolDate="09/01/2029"; Status="Soporte Extendido"; IsEol=$false },
        [PSCustomObject]@{ Name="DC03-CALI"; IP="192.168.30.10"; OS="Windows Server 2012 R2 Datacenter"; EolDate="10/10/2023"; Status="Vencido / Sin Soporte"; IsEol=$true }
    )

    # Cuentas con SPN (Kerberoasting)
    $spnUsers = @(
        [PSCustomObject]@{ SamAccountName="svc_sql_prod"; Name="Servicio Motor SQL Produccion"; SPNs="MSSQLSvc/sql01.corp.empresa.local:1433"; PasswordLastSet=(Get-Date).AddDays(-610); Risk="CRITICO (Clave > 12 meses)" },
        [PSCustomObject]@{ SamAccountName="svc_iis_portal"; Name="Pool IIS Portal Web Transaccional"; SPNs="HTTP/portal.corp.empresa.local"; PasswordLastSet=(Get-Date).AddDays(-380); Risk="ALTO (Clave > 12 meses)" },
        [PSCustomObject]@{ SamAccountName="svc_powerbi_gw"; Name="Gateway Power BI Corporativo"; SPNs="MSSQLSvc/bi-report.empresa.local"; PasswordLastSet=(Get-Date).AddDays(-85); Risk="MEDIO (Migrar a gMSA)" }
    )

    # Autoridades de Certificacion (AD CS / PKI)
    $certAuthorities = @(
        [PSCustomObject]@{ Name="CORP-ROOT-CA"; Host="CA01-MED.corp.empresa.local"; Type="Enterprise Root CA"; Status="En Linea (Ping Certutil OK)" }
    )
}
else {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "El modulo ActiveDirectory de RSAT no esta instalado. Ejecuta con -Demo para ver una prueba o instala RSAT."
        return
    }
    Import-Module ActiveDirectory

    Write-Host "[*] Consultando informacion del dominio y bosque..." -ForegroundColor Green
    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot
    
    $forest = Get-ADForest
    $functionalLevel = "$($domain.DomainMode)"
    if ($forest.ForestMode) {
        $functionalLevel += " (Bosque: $($forest.ForestMode))"
    }

    # Papelera de reciclaje
    $recycleFeature = Get-ADOptionalFeature -Filter { Name -like "*Recycle Bin*" }
    if ($recycleFeature -and $recycleFeature.EnabledScopes.Count -gt 0) {
        $recycleBinStatus = "Habilitada (Proteccion activa)"
    } else {
        $recycleBinStatus = "ALERTA: Deshabilitada (Riesgo en recuperacion de objetos)"
    }

    # Auditoria krbtgt
    $krbtgtObj = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, Created
    if ($krbtgtObj) {
        $kDate = if ($krbtgtObj.PasswordLastSet) { $krbtgtObj.PasswordLastSet } else { $krbtgtObj.Created }
        $kDays = [Math]::Floor(((Get-Date) - $kDate).TotalDays)
        $kRisk = if ($kDays -gt 180) { "CRITICO (>180 dias sin rotacion)" } elseif ($kDays -gt 90) { "PRECAUCION (>90 dias)" } else { "Saludable (<90 dias)" }
        $kAction = if ($kDays -gt 180) { "Ejecutar doble rotacion con intervalo de replicacion" } else { "Mantener rotacion periodica semestral" }
        
        $krbtgtInfo = [PSCustomObject]@{
            Account         = "krbtgt"
            PasswordLastSet = $kDate
            Days            = $kDays
            Risk            = $kRisk
            Action          = $kAction
        }
    }

    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    Write-Host "[*] Auditando usuarios y cuentas de servicio..." -ForegroundColor Green
    $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordNeverExpires, Title, PasswordLastSet, ServicePrincipalNames, Description
    $totalUsers = $allUsers.Count
    
    $allComputers = Get-ADComputer -Filter * -Properties LastLogonDate, "ms-Mcs-AdmPwd", "msLAPS-Password"
    $totalComputers = $allComputers.Count
    
    $inactiveUsers = $allUsers | Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $cutoffDate }
    $pwdNeverExpires = $allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true }
    
    # SPNs en cuentas de usuario (Kerberoasting)
    $spnCandidates = $allUsers | Where-Object { $_.ServicePrincipalNames.Count -gt 0 -and $_.SamAccountName -ne "krbtgt" -and $_.SamAccountName -notlike "*$" }
    foreach ($su in $spnCandidates) {
        $pwdAgeDays = if ($su.PasswordLastSet) { [Math]::Floor(((Get-Date) - $su.PasswordLastSet).TotalDays) } else { 999 }
        $riskStr = if ($pwdAgeDays -gt 365) { "CRITICO (Clave > 12 meses)" } elseif ($pwdAgeDays -gt 180) { "ALTO (Clave > 180 d)" } else { "MEDIO (Migrar a gMSA)" }
        $spnList = ($su.ServicePrincipalNames | Select-Object -First 2) -join ", "
        $spnUsers += [PSCustomObject]@{
            SamAccountName  = $su.SamAccountName
            Name            = $(if ($su.Description) { $su.Description } else { $su.Name })
            SPNs            = $spnList
            PasswordLastSet = $su.PasswordLastSet
            Risk            = $riskStr
        }
    }

    # Domain Admins
    $daGroup = Get-ADGroupMember -Identity "Domain Admins"
    foreach ($member in $daGroup) {
        $u = $allUsers | Where-Object { $_.DistinguishedName -eq $member.DistinguishedName }
        $status = "Activo"
        if ($u.LastLogonDate -and $u.LastLogonDate -lt $cutoffDate) {
            $status = "ALERTA: Inactivo > $DaysInactive dias"
        }
        $domainAdmins += [PSCustomObject]@{
            SamAccountName = $member.SamAccountName
            Name           = $member.name
            LastLogon      = $u.LastLogonDate
            Status         = $status
        }
    }
    
    # LAPS
    $lapsEnabledCount = ($allComputers | Where-Object { $_."ms-Mcs-AdmPwd" -ne $null -or $_."msLAPS-Password" -ne $null }).Count
    $totalLapsEnabled = $lapsEnabledCount
    $totalNonLaps = [Math]::Max(0, ($totalComputers - $lapsEnabledCount))
    
    # Domain Controllers y EOL
    Write-Host "[*] Evaluando Domain Controllers y ciclo de vida de SO..." -ForegroundColor Green
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        $eolData = Get-EolInfo $dc.OperatingSystem
        $domainControllers += [PSCustomObject]@{
            Name    = $dc.Name
            IP      = $dc.IPv4Address
            OS      = $dc.OperatingSystem
            EolDate = $eolData.EolDate
            Status  = $eolData.Status
            IsEol   = $eolData.IsEol
        }
    }

    # Autoridades de Certificacion (AD CS / PKI) via certutil
    Write-Host "[*] Verificando autoridades de certificacion (AD CS / PKI)..." -ForegroundColor Green
    try {
        $certutilPing = certutil -config - -ping 2>&1
        $pingText = [string]::Join("`n", $certutilPing)
        if ($pingText -match 'Server\s+"([^"]+)"\s+ICertRequest2 interface is alive') {
            $caHost = $matches[1]
            $certAuthorities += [PSCustomObject]@{
                Name   = "Enterprise CA Activa"
                Host   = $caHost
                Type   = "Enterprise CA"
                Status = "En Linea (Ping Certutil OK)"
            }
        } elseif ($pingText -match 'No Certificate Authorities were found' -or $pingText -match 'No se encontraron entidades') {
            # No hay CAs integradas
        } else {
            $certAuthorities += [PSCustomObject]@{
                Name   = "AD CS Detectado"
                Host   = "Dominio Local"
                Type   = "PKI Corporativa"
                Status = "Respuesta Parcial / Requiere Revision"
            }
        }
    } catch {
        # Certutil no disponible o sin privilegios de consulta
    }
}

# Calculo de puntuacion de salud (0-100)
$score = 100

# 1. Penalizacion por usuarios inactivos
$pctInactiveUsers = if ($totalUsers -gt 0) { [Math]::Round(($inactiveUsers.Count / $totalUsers) * 100, 1) } else { 0 }
if ($pctInactiveUsers -gt 10) { $score -= 15 }
elseif ($pctInactiveUsers -gt 3) { $score -= 8 }

# 2. Penalizacion por Domain Admins inactivos
$inactiveDAs = @($domainAdmins | Where-Object { $_.Status -match "ALERTA" }).Count
if ($inactiveDAs -gt 0) { $score -= 20 }

# 3. Penalizacion por cobertura de LAPS
$lapsCoverage = if ($totalComputers -gt 0) { [Math]::Round(($totalLapsEnabled / $totalComputers) * 100, 1) } else { 0 }
if ($lapsCoverage -lt 30) { $score -= 20 }
elseif ($lapsCoverage -lt 80) { $score -= 10 }

# 4. Penalizacion por krbtgt > 180 dias (Riesgo Golden Ticket)
$krbtgtDaysVal = if ($krbtgtInfo) { $krbtgtInfo.Days } else { 0 }
if ($krbtgtDaysVal -gt 180) { $score -= 15 }
elseif ($krbtgtDaysVal -gt 90) { $score -= 5 }

# 5. Penalizacion por Domain Controllers fuera de soporte (EOL)
$countEolDcs = @($domainControllers | Where-Object { $_.IsEol -eq $true }).Count
if ($countEolDcs -gt 0) { $score -= 20 }

# 6. Penalizacion por cuentas de servicio SPN vulnerables a Kerberoast
$countSpnUsers = @($spnUsers).Count
if ($countSpnUsers -gt 5) { $score -= 10 }
elseif ($countSpnUsers -gt 0) { $score -= 5 }

# 7. Penalizacion por contraseñas que nunca expiran
$countPwdNever = @($pwdNeverExpires).Count
if ($countPwdNever -gt 10) { $score -= 10 }
elseif ($countPwdNever -gt 3) { $score -= 5 }

# 8. Papelera de reciclaje deshabilitada
if ($recycleBinStatus -match "ALERTA") { $score -= 5 }

$score = [Math]::Max(10, [Math]::Min(100, $score))

$scoreColor = "#10b981"
$scoreGrade = "RIESGO BAJO (SALUDABLE)"
if ($score -lt 65) {
    $scoreColor = "#ef4444"
    $scoreGrade = "RIESGO CRITICO (ACCION REQUERIDA)"
} elseif ($score -lt 85) {
    $scoreColor = "#f59e0b"
    $scoreGrade = "RIESGO MEDIO (PRECAUCION)"
}

Write-Host "[*] Puntuacion calculada: $score / 100 ($scoreGrade)" -ForegroundColor Cyan

# Construccion de filas de tablas HTML

# 1. krbtgt
$krbtgtRows = ""
if ($krbtgtInfo) {
    $kBadge = if ($krbtgtInfo.Days -gt 180) { "badge-danger" } elseif ($krbtgtInfo.Days -gt 90) { "badge-warning" } else { "badge-success" }
    $kDateStr = if ($krbtgtInfo.PasswordLastSet) { $krbtgtInfo.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Desconocido" }
    $krbtgtRows = "<tr><td><strong>$($krbtgtInfo.Account)</strong></td><td>$kDateStr</td><td>$($krbtgtInfo.Days) dias</td><td><span class='badge $kBadge'>$($krbtgtInfo.Risk)</span></td><td>$($krbtgtInfo.Action)</td></tr>"
} else {
    $krbtgtRows = "<tr><td colspan='5' style='text-align:center;'>No se pudo consultar informacion de la cuenta krbtgt.</td></tr>"
}

# 2. SPNs (Kerberoasting)
$spnRows = ""
if ($spnUsers.Count -gt 0) {
    foreach ($s in $spnUsers) {
        $sBadge = if ($s.Risk -match "CRITICO") { "badge-danger" } elseif ($s.Risk -match "ALTO") { "badge-warning" } else { "badge-warning" }
        $sDateStr = if ($s.PasswordLastSet) { $s.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Nunca" }
        $spnRows += "<tr><td><strong>$($s.SamAccountName)</strong></td><td>$($s.Name)</td><td><code style='font-size:12px; color:#38bdf8;'>$($s.SPNs)</code></td><td>$sDateStr</td><td><span class='badge $sBadge'>$($s.Risk)</span></td></tr>`n"
    }
} else {
    $spnRows = "<tr><td colspan='5' style='text-align:center; color:#34d399;'>No se detectaron cuentas de usuario con SPNs registrados (Riesgo mitigado).</td></tr>"
}

# 3. Domain Controllers & EOL
$dcRows = ""
foreach ($dc in $domainControllers) {
    $dcBadge = if ($dc.IsEol -eq $true) { "badge-danger" } elseif ($dc.Status -match "Extendido") { "badge-warning" } else { "badge-success" }
    $dcRows += "<tr><td><strong>$($dc.Name)</strong></td><td>$($dc.IP)</td><td>$($dc.OS)</td><td><strong>$($dc.EolDate)</strong></td><td><span class='badge $dcBadge'>$($dc.Status)</span></td></tr>`n"
}

# 4. Autoridades de Certificacion (AD CS / PKI)
$caRows = ""
if ($certAuthorities.Count -gt 0) {
    foreach ($ca in $certAuthorities) {
        $caRows += "<tr><td><strong>$($ca.Name)</strong></td><td>$($ca.Host)</td><td>$($ca.Type)</td><td><span class='badge badge-success'>$($ca.Status)</span></td></tr>`n"
    }
} else {
    $caRows = "<tr><td colspan='4' style='text-align:center; color:#94a3b8;'>No se detectaron servidores AD CS / PKI corporativos activos mediante ping certutil.</td></tr>"
}

# 5. Usuarios inactivos
$inactiveRows = ""
foreach ($u in $inactiveUsers) {
    $logonStr = if ($u.LastLogonDate) { $u.LastLogonDate.ToString("yyyy-MM-dd") } else { "Nunca" }
    $inactiveRows += "<tr><td><strong>$($u.SamAccountName)</strong></td><td>$($u.Name)</td><td>$($u.Title)</td><td>$logonStr</td><td><span class='badge badge-danger'>Inactivo > $DaysInactive d</span></td></tr>`n"
}

# 6. Domain Admins
$daRows = ""
foreach ($da in $domainAdmins) {
    $badgeClass = if ($da.Status -match "ALERTA") { "badge-danger" } else { "badge-success" }
    $logonStr = if ($da.LastLogon) { $da.LastLogon.ToString("yyyy-MM-dd") } else { "Nunca" }
    $daRows += "<tr><td><strong>$($da.SamAccountName)</strong></td><td>$($da.Name)</td><td>$logonStr</td><td><span class='badge $badgeClass'>$($da.Status)</span></td></tr>`n"
}

# 7. Contraseñas que nunca expiran
$pwdRows = ""
foreach ($p in $pwdNeverExpires) {
    $setStr = if ($p.PasswordLastSet) { $p.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Nunca" }
    $pwdRows += "<tr><td><strong>$($p.SamAccountName)</strong></td><td>$($p.Name)</td><td>$setStr</td><td><span class='badge badge-warning'>Sin Expiracion</span></td></tr>`n"
}

# Cargar plantilla y reemplazar tokens
$templateContent = Get-Content -Path $templatePath -Raw -Encoding UTF8

$htmlOutput = $templateContent
$htmlOutput = $htmlOutput.Replace("{{DOMAIN}}", $domainName)
$htmlOutput = $htmlOutput.Replace("{{FUNCTIONAL_LEVEL}}", $functionalLevel)
$htmlOutput = $htmlOutput.Replace("{{RECYCLE_BIN_STATUS}}", $recycleBinStatus)
$htmlOutput = $htmlOutput.Replace("{{DATE}}", (Get-Date -Format "yyyy-MM-dd HH:mm"))
$htmlOutput = $htmlOutput.Replace("{{DAYS_INACTIVE}}", "$DaysInactive")

# Scores
$htmlOutput = $htmlOutput.Replace("{{SCORE}}", "$score")
$htmlOutput = $htmlOutput.Replace("{{SCORE_COLOR}}", $scoreColor)
$htmlOutput = $htmlOutput.Replace("{{SCORE_GRADE}}", $scoreGrade)

# KPI 1: krbtgt
$krbtgtStatusText = if ($krbtgtDaysVal -gt 180) { "Requiere Rotacion Urgente" } elseif ($krbtgtDaysVal -gt 90) { "Revision Sugerida" } else { "Clave Saludable" }
$krbtgtColorText = if ($krbtgtDaysVal -gt 180) { "#f87171" } elseif ($krbtgtDaysVal -gt 90) { "#fbbf24" } else { "#34d399" }
$htmlOutput = $htmlOutput.Replace("{{KRBTGT_DAYS}}", "$krbtgtDaysVal")
$htmlOutput = $htmlOutput.Replace("{{KRBTGT_COLOR}}", $krbtgtColorText)
$htmlOutput = $htmlOutput.Replace("{{KRBTGT_STATUS}}", $krbtgtStatusText)

# KPI 2: LAPS
$lapsColorText = if ($lapsCoverage -lt 50) { "#f87171" } elseif ($lapsCoverage -lt 80) { "#fbbf24" } else { "#34d399" }
$htmlOutput = $htmlOutput.Replace("{{LAPS_COVERAGE}}", "$lapsCoverage")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_LAPS_ENABLED}}", "$totalLapsEnabled")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_COMPUTERS}}", "$totalComputers")
$htmlOutput = $htmlOutput.Replace("{{LAPS_COLOR}}", $lapsColorText)

# KPI 3: Inactive users
$htmlOutput = $htmlOutput.Replace("{{COUNT_INACTIVE_USERS}}", "$($inactiveUsers.Count)")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_USERS}}", "$totalUsers")
$htmlOutput = $htmlOutput.Replace("{{PCT_INACTIVE_USERS}}", "$pctInactiveUsers")

# KPI 4: Domain Admins
$daColorText = if ($inactiveDAs -gt 0) { "#f87171" } else { "#34d399" }
$htmlOutput = $htmlOutput.Replace("{{INACTIVE_DAS}}", "$inactiveDAs")
$htmlOutput = $htmlOutput.Replace("{{COUNT_DOMAIN_ADMINS}}", "$($domainAdmins.Count)")
$htmlOutput = $htmlOutput.Replace("{{DA_COLOR}}", $daColorText)

# KPI 5: SPN users (Kerberoast)
$spnColorText = if ($spnUsers.Count -gt 0) { "#fbbf24" } else { "#34d399" }
$htmlOutput = $htmlOutput.Replace("{{COUNT_SPN_USERS}}", "$($spnUsers.Count)")
$htmlOutput = $htmlOutput.Replace("{{SPN_COLOR}}", $spnColorText)

# KPI 6: DC EOL
$dcEolColorText = if ($countEolDcs -gt 0) { "#f87171" } else { "#34d399" }
$htmlOutput = $htmlOutput.Replace("{{COUNT_EOL_DCS}}", "$countEolDcs")
$htmlOutput = $htmlOutput.Replace("{{COUNT_DCS}}", "$($domainControllers.Count)")
$htmlOutput = $htmlOutput.Replace("{{DC_EOL_COLOR}}", $dcEolColorText)

# Tablas y listas
$htmlOutput = $htmlOutput.Replace("{{COUNT_CAS}}", "$($certAuthorities.Count)")
$htmlOutput = $htmlOutput.Replace("{{COUNT_PWD_NEVER}}", "$($pwdNeverExpires.Count)")
$htmlOutput = $htmlOutput.Replace("{{KRBTGT_TABLE}}", $krbtgtRows)
$htmlOutput = $htmlOutput.Replace("{{SPN_TABLE}}", $spnRows)
$htmlOutput = $htmlOutput.Replace("{{DCS_TABLE}}", $dcRows)
$htmlOutput = $htmlOutput.Replace("{{CAS_TABLE}}", $caRows)
$htmlOutput = $htmlOutput.Replace("{{INACTIVE_USERS_TABLE}}", $inactiveRows)
$htmlOutput = $htmlOutput.Replace("{{DOMAIN_ADMINS_TABLE}}", $daRows)
$htmlOutput = $htmlOutput.Replace("{{PWD_NEVER_TABLE}}", $pwdRows)

[System.IO.File]::WriteAllText($OutputPath, $htmlOutput, [System.Text.Encoding]::UTF8)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[OK] Reporte v1.1.0 generado exitosamente en:" -ForegroundColor Green
Write-Host "     $OutputPath" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
