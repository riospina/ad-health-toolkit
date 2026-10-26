# AD-Health-Toolkit 🛡️
> **Herramienta Open-Source de Auto-Diagnóstico y Auditoría de Seguridad para Active Directory**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20%7C%202019%20%7C%202022%20%7C%202025-0078D4.svg)](https://www.microsoft.com/windows-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Read-Only](https://img.shields.io/badge/Mode-100%25%20Read--Only-success.svg)](#seguridad)

**AD-Health-Toolkit** permite a administradores de sistemas, jefes de TI y auditores evaluar la salud y postura de seguridad de un dominio de Active Directory en menos de 3 minutos.

Genera un **Dashboard Ejecutivo interactivo en HTML** con una puntuación de riesgo (0 a 100) y el inventario detallado de vulnerabilidades operativas críticas, sin requerir software costoso ni dependencias de terceros.

---

## ⚡ ¿Qué evalúa el diagnóstico?

1. **Cuentas de Usuario Inactivas:** Identifica usuarios habilitados que no inician sesión hace más de 60 o 90 días (puerta de entrada principal para atacantes o exempleados).
2. **Cobertura de Windows LAPS:** Calcula el porcentaje de estaciones y servidores que tienen protegida su contraseña de administrador local contra ataques de movimiento lateral (*Pass-the-Hash*).
3. **Auditoría de 'Domain Admins':** Detecta cuentas administrativas en riesgo (sin rotación de credenciales o inactivas).
4. **Contraseñas que Nunca Expiran:** Lista cuentas con la directiva `PasswordNeverExpires` habilitada.
5. **Salud de Controladores de Dominio (DCs):** Comprueba el estado de comunicación y sistemas operativos de los DCs de la infraestructura.

---

## 🚀 Inicio Rápido

### Requisitos
* Windows 10/11 o Windows Server con el módulo de PowerShell `ActiveDirectory` (RSAT).
* Permisos estándar de lectura en el dominio (no requiere privilegios de Domain Admin para auditar).

### 1. Clonar el repositorio
```powershell
git clone https://github.com/tu-usuario/ad-health-toolkit.git
cd ad-health-toolkit\src
```

### 2. Ejecutar la auditoría en tu dominio
```powershell
# Auditoría estándar (inactividad > 90 días)
.\Get-ADHealthReport.ps1

# Personalizar el umbral de inactividad a 60 días
.\Get-ADHealthReport.ps1 -DaysInactive 60
```

### 3. Modo Demostración (Sin Domain Controller)
Si estás probando la herramienta en un equipo local fuera de dominio:
```powershell
.\Get-ADHealthReport.ps1 -Demo
```
*El script generará un reporte de ejemplo completo con datos simulados en la carpeta `reports/`.*

---

## 🔒 Seguridad y Garantía de Solo Lectura

* **100% Read-Only:** Este script **únicamente realiza consultas LDAP/AD**. No altera atributos, no deshabilita usuarios, no modifica directivas de grupo ni escribe en la base de datos `ntds.dit`.
* **Sin telemetría ni llamadas externas:** Toda la información recolectada permanece estrictamente en tu máquina local.

---

## 💼 Servicios Profesionales & Remediación

¿Ejecutaste el diagnóstico y encontraste hallazgos críticos en tu infraestructura?

Ofrezco servicios de consultoría especializada independiente para empresas:
* **Implementación de Windows LAPS nativo** en servidores y estaciones de trabajo.
* **Saneamiento seguro de Active Directory** (limpieza masiva de cuentas y GPOs sin interrupción operativa).
* **Hardening de servidores Windows y Linux** bajo mejores prácticas y marcos de cumplimiento.

**Contacto:**
* 👤 **Ing. Ricardo Ospina Franco** (Especialista en Infraestructura TI & Sysadmin)
* 📧 **Email:** [rof.ospina@gmail.com](mailto:rof.ospina@gmail.com)
* 📱 **WhatsApp:** [+57 318 375 8111](https://wa.me/573183758111)
* 🌐 **LinkedIn:** [linkedin.com/in/ricardo-ospina-f](https://www.linkedin.com/in/ricardo-ospina-f)

---

## 📄 Licencia
Este proyecto está bajo la Licencia [MIT](LICENSE).
