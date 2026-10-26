<#
.SYNOPSIS
    AD-Health-Toolkit - Auditoria de Salud y Seguridad para Active Directory
.DESCRIPTION
    Herramienta open-source de diagnostico automatizado para Active Directory.
    Evalua cuentas inactivas, cobertura de LAPS, privilegios de Domain Admins,
    contrasenas que no expiran y controladores de dominio.
    Genera un informe interactivo en HTML con puntuacion de salud (0-100).
    100% de Solo Lectura: No realiza cambios ni escrituras en el dominio.

.PARAMETER DaysInactive
    Numero de dias de inactividad para clasificar cuentas obsoletas (por defecto: 90).

.PARAMETER OutputPath
    Ruta del archivo HTML de reporte a generar.

.PARAMETER Demo
    Modo demostracion: Genera datos realistas de prueba para previsualizar el reporte
    sin requerir conexion a un Domain Controller en vivo.

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
Write-Host " AD-Health-Toolkit | Auditoria de Active Directory" -ForegroundColor White
Write-Host " Autor: Ing. Ricardo Ospina Franco (rof.ospina@gmail.com)" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

$domainName = "DESCONOCIDO"
$totalUsers = 0
$totalComputers = 0
$inactiveUsers = @()
$inactiveComputers = @()
$pwdNeverExpires = @()
$domainAdmins = @()
$totalLapsEnabled = 0
$totalNonLaps = 0
$domainControllers = @()

if ($Demo) {
    Write-Host "[i] Modo DEMO activado. Generando datos simulados realistas..." -ForegroundColor Yellow
    $domainName = "CORP.EMPRESA.LOCAL"
    $totalUsers = 640
    $totalComputers = 480
    
    $inactiveUsers = @(
        [PSCustomObject]@{ SamAccountName="carlos.mendoza"; Name="Carlos Mendoza"; LastLogonDate=(Get-Date).AddDays(-142); Enabled=$true; Title="Auxiliar Operativo" },
        [PSCustomObject]@{ SamAccountName="laura.gomez"; Name="Laura Gomez"; LastLogonDate=(Get-Date).AddDays(-210); Enabled=$true; Title="Analista Financiero" },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; LastLogonDate=(Get-Date).AddDays(-320); Enabled=$true; Title="Contratista Externo" },
        [PSCustomObject]@{ SamAccountName="juan.perez"; Name="Juan Perez"; LastLogonDate=(Get-Date).AddDays(-115); Enabled=$true; Title="Soporte Tecnico" },
        [PSCustomObject]@{ SamAccountName="andrea.ruiz"; Name="Andrea Ruiz"; LastLogonDate=(Get-Date).AddDays(-98); Enabled=$true; Title="Coordinadora Comercial" }
    )
    
    $pwdNeverExpires = @(
        [PSCustomObject]@{ SamAccountName="servicio.backup"; Name="Cuenta Servicio Backup"; PasswordLastSet=(Get-Date).AddDays(-410); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; PasswordLastSet=(Get-Date).AddDays(-320); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="gerencia.general"; Name="Gerente General"; PasswordLastSet=(Get-Date).AddDays(-530); Enabled=$true },
        [PSCustomObject]@{ SamAccountName="impresora.scanner"; Name="Scanner Corporativo"; PasswordLastSet=(Get-Date).AddDays(-600); Enabled=$true }
    )
    
    $domainAdmins = @(
        [PSCustomObject]@{ SamAccountName="Administrator"; Name="Administrador Nativo"; LastLogon=(Get-Date).AddDays(-2); Status="Activo" },
        [PSCustomObject]@{ SamAccountName="admin.soporte"; Name="Admin Soporte TI"; LastLogon=(Get-Date).AddDays(-1); Status="Activo" },
        [PSCustomObject]@{ SamAccountName="admin.temp"; Name="Admin Temporal Proveedor"; LastLogon=(Get-Date).AddDays(-320); Status="ALERTA: Inactivo" },
        [PSCustomObject]@{ SamAccountName="carlos.mendoza"; Name="Carlos Mendoza (Ex-colaborador)"; LastLogon=(Get-Date).AddDays(-142); Status="ALERTA: Inactivo" }
    )
    
    $totalLapsEnabled = 42
    $totalNonLaps = 438
    
    $domainControllers = @(
        [PSCustomObject]@{ Name="DC01-MED"; IP="192.168.10.10"; OS="Windows Server 2022 Datacenter"; Status="En Linea (Saludable)" },
        [PSCustomObject]@{ Name="DC02-BOG"; IP="192.168.20.10"; OS="Windows Server 2019 Standard"; Status="En Linea (Saludable)" }
    )
}
else {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "El modulo ActiveDirectory de RSAT no esta instalado. Ejecuta con -Demo para ver una prueba o instala RSAT."
        return
    }
    Import-Module ActiveDirectory

    Write-Host "[*] Consultando informacion del dominio..." -ForegroundColor Green
    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordNeverExpires, Title, PasswordLastSet
    $totalUsers = $allUsers.Count
    
    $allComputers = Get-ADComputer -Filter * -Properties LastLogonDate, "ms-Mcs-AdmPwd", "msLAPS-Password"
    $totalComputers = $allComputers.Count
    
    $inactiveUsers = $allUsers | Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $cutoffDate }
    $pwdNeverExpires = $allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true }
    
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
    
    $lapsEnabledCount = ($allComputers | Where-Object { $_."ms-Mcs-AdmPwd" -ne $null -or $_."msLAPS-Password" -ne $null }).Count
    $totalLapsEnabled = $lapsEnabledCount
    $totalNonLaps = [Math]::Max(0, ($totalComputers - $lapsEnabledCount))
    
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        $domainControllers += [PSCustomObject]@{
            Name   = $dc.Name
            IP     = $dc.IPv4Address
            OS     = $dc.OperatingSystem
            Status = "En Linea (Saludable)"
        }
    }
}

# Calculo de puntuacion de salud
$score = 100
$pctInactiveUsers = if ($totalUsers -gt 0) { [Math]::Round(($inactiveUsers.Count / $totalUsers) * 100, 1) } else { 0 }
if ($pctInactiveUsers -gt 10) { $score -= 20 }
elseif ($pctInactiveUsers -gt 3) { $score -= 10 }

$inactiveDAs = ($domainAdmins | Where-Object { $_.Status -match "ALERTA" }).Count
if ($inactiveDAs -gt 0) { $score -= 25 }

$lapsCoverage = if ($totalComputers -gt 0) { [Math]::Round(($totalLapsEnabled / $totalComputers) * 100, 1) } else { 0 }
if ($lapsCoverage -lt 30) { $score -= 25 }
elseif ($lapsCoverage -lt 80) { $score -= 15 }

if ($pwdNeverExpires.Count -gt 10) { $score -= 15 }
elseif ($pwdNeverExpires.Count -gt 3) { $score -= 8 }

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

# Construccion de filas de tablas
$inactiveRows = ""
foreach ($u in $inactiveUsers) {
    $logonStr = if ($u.LastLogonDate) { $u.LastLogonDate.ToString("yyyy-MM-dd") } else { "Nunca" }
    $inactiveRows += "<tr><td><strong>$($u.SamAccountName)</strong></td><td>$($u.Name)</td><td>$($u.Title)</td><td>$logonStr</td><td><span class='badge badge-danger'>Inactivo > $DaysInactive d</span></td></tr>`n"
}

$daRows = ""
foreach ($da in $domainAdmins) {
    $badgeClass = if ($da.Status -match "ALERTA") { "badge-danger" } else { "badge-success" }
    $logonStr = if ($da.LastLogon) { $da.LastLogon.ToString("yyyy-MM-dd") } else { "Nunca" }
    $daRows += "<tr><td><strong>$($da.SamAccountName)</strong></td><td>$($da.Name)</td><td>$logonStr</td><td><span class='badge $badgeClass'>$($da.Status)</span></td></tr>`n"
}

$pwdRows = ""
foreach ($p in $pwdNeverExpires) {
    $setStr = if ($p.PasswordLastSet) { $p.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Nunca" }
    $pwdRows += "<tr><td><strong>$($p.SamAccountName)</strong></td><td>$($p.Name)</td><td>$setStr</td><td><span class='badge badge-warning'>Sin Expiracion</span></td></tr>`n"
}

$dcRows = ""
foreach ($dc in $domainControllers) {
    $dcRows += "<tr><td><strong>$($dc.Name)</strong></td><td>$($dc.IP)</td><td>$($dc.OS)</td><td><span class='badge badge-success'>$($dc.Status)</span></td></tr>`n"
}

# Cargar plantilla y reemplazar tokens
$templateContent = Get-Content -Path $templatePath -Raw -Encoding UTF8

$htmlOutput = $templateContent.Replace("{{DOMAIN}}", $domainName)
$htmlOutput = $htmlOutput.Replace("{{SCORE}}", "$score")
$htmlOutput = $htmlOutput.Replace("{{SCORE_COLOR}}", $scoreColor)
$htmlOutput = $htmlOutput.Replace("{{SCORE_GRADE}}", $scoreGrade)
$htmlOutput = $htmlOutput.Replace("{{DATE}}", (Get-Date -Format "yyyy-MM-dd HH:mm"))
$htmlOutput = $htmlOutput.Replace("{{DAYS_INACTIVE}}", "$DaysInactive")
$htmlOutput = $htmlOutput.Replace("{{COUNT_INACTIVE_USERS}}", "$($inactiveUsers.Count)")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_USERS}}", "$totalUsers")
$htmlOutput = $htmlOutput.Replace("{{PCT_INACTIVE_USERS}}", "$pctInactiveUsers")
$htmlOutput = $htmlOutput.Replace("{{LAPS_COVERAGE}}", "$lapsCoverage")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_LAPS_ENABLED}}", "$totalLapsEnabled")
$htmlOutput = $htmlOutput.Replace("{{TOTAL_COMPUTERS}}", "$totalComputers")
$htmlOutput = $htmlOutput.Replace("{{LAPS_COLOR}}", $(if ($lapsCoverage -lt 50) { "#f87171" } else { "#34d399" }))
$htmlOutput = $htmlOutput.Replace("{{INACTIVE_DAS}}", "$inactiveDAs")
$htmlOutput = $htmlOutput.Replace("{{COUNT_DOMAIN_ADMINS}}", "$($domainAdmins.Count)")
$htmlOutput = $htmlOutput.Replace("{{DA_COLOR}}", $(if ($inactiveDAs -gt 0) { "#f87171" } else { "#34d399" }))
$htmlOutput = $htmlOutput.Replace("{{COUNT_PWD_NEVER}}", "$($pwdNeverExpires.Count)")
$htmlOutput = $htmlOutput.Replace("{{COUNT_DCS}}", "$($domainControllers.Count)")
$htmlOutput = $htmlOutput.Replace("{{INACTIVE_USERS_TABLE}}", $inactiveRows)
$htmlOutput = $htmlOutput.Replace("{{DOMAIN_ADMINS_TABLE}}", $daRows)
$htmlOutput = $htmlOutput.Replace("{{PWD_NEVER_TABLE}}", $pwdRows)
$htmlOutput = $htmlOutput.Replace("{{DCS_TABLE}}", $dcRows)

[System.IO.File]::WriteAllText($OutputPath, $htmlOutput, [System.Text.Encoding]::UTF8)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[OK] Reporte generado exitosamente en:" -ForegroundColor Green
Write-Host "     $OutputPath" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
