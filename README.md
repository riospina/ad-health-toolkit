# AD-Health-Toolkit 🛡️
> **Herramienta Open-Source de Auto-Diagnóstico y Auditoría de Seguridad para Active Directory**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%20%7C%202019%20%7C%202022%20%7C%202025-0078D4.svg)](https://www.microsoft.com/windows-server)
[![Release](https://img.shields.io/badge/Release-v1.1.0-blueviolet.svg)](https://github.com/riospina/ad-health-toolkit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Read-Only](https://img.shields.io/badge/Mode-100%25%20Read--Only-success.svg)](#seguridad)

**AD-Health-Toolkit** permite a administradores de sistemas, jefes de TI y auditores evaluar la salud y postura de seguridad de un dominio corporativo de Active Directory en menos de 3 minutos.

Genera un **Dashboard Ejecutivo interactivo en HTML** con una puntuación de riesgo (0 a 100), 6 indicadores clave (KPIs) y el inventario detallado de vulnerabilidades operativas críticas, sin requerir software costoso ni dependencias de terceros.

---

## ⚡ ¿Qué evalúa el diagnóstico (v1.1.0)?

1. **🔑 Antigüedad de la Cuenta `krbtgt` (Golden Ticket):**
   Calcula la antigüedad de la última rotación de contraseña de `krbtgt`. Alerta críticamente si supera los 180 días, previniendo la persistencia de tickets Kerberos forjados (*Golden Tickets*).
2. **🤖 Cuentas de Servicio con SPN (Kerberoasting):**
   Identifica cuentas de usuario convencionales registradas con `ServicePrincipalName` (SPN) expuestas a extracción offline de credenciales (Kerberoast) y evalúa su antigüedad de clave para orientar la migración a **gMSA (Group Managed Service Accounts)**.
3. **🖥️ Ciclo de Vida y End-of-Life (EOL) de Controladores de Dominio:**
   Mapea los sistemas operativos de todos los DCs del dominio contra la matriz de ciclo de vida oficial de Microsoft (Windows Server 2008, 2012, 2016, 2019, 2022, 2025) señalando servidores obsoletos vulnerables a *Zerologon* o *PrintNightmare*.
4. **📜 Autoridades de Certificación Corporativas (AD CS / PKI):**
   Audita la conectividad y estado operativo de las CAs empresariales del bosque mediante diagnóstico `certutil -config - -ping`.
5. **🛡️ Cobertura de Windows LAPS:**
   Calcula el porcentaje de estaciones y servidores que tienen protegida su contraseña de administrador local (LAPS clásico o Windows LAPS nativo) para frenar el movimiento lateral (*Pass-the-Hash*).
6. **👥 Usuarios Inactivos Habilitados:**
   Filtra cuentas con credenciales vigentes que no han iniciado sesión en más de 60 o 90 días (puerta de entrada principal para atacantes o exempleados).
7. **👑 Auditoría de 'Domain Admins':**
   Evalúa cuentas con privilegios administrativos totales sobre el bosque, detectando administradores inactivos o sin rotación de contraseña.
8. **⚠️ Contraseñas que Nunca Expiran:**
   Inventaria cuentas con el flag `PasswordNeverExpires` habilitado.
9. **♻️ Papelera de Reciclaje de AD (Recycle Bin):**
   Verifica si la característica opcional de Papelera de Reciclaje está activada en el bosque para recuperación inmediata de objetos borrados.

---

## 🚀 Inicio Rápido

### Requisitos
* Windows 10/11 o Windows Server con el módulo de PowerShell `ActiveDirectory` (RSAT).
* Permisos estándar de lectura en el dominio (no requiere privilegios de Domain Admin para auditar).

### 1. Clonar el repositorio
```powershell
git clone https://github.com/riospina/ad-health-toolkit.git
cd ad-health-toolkit\src
```

### 2. Ejecutar la auditoría en tu dominio
```powershell
# Auditoría estándar (criterio de inactividad > 90 días)
.\Get-ADHealthReport.ps1

# Personalizar el umbral de inactividad (ej. 60 días)
.\Get-ADHealthReport.ps1 -DaysInactive 60
```

### 3. Modo Demostración (Sin Domain Controller en vivo)
Si deseas explorar el reporte interactivo en una máquina local o fuera de dominio:
```powershell
.\Get-ADHealthReport.ps1 -Demo
```
*El script generará un reporte ejecutivo completo con datos simulados en la carpeta `reports/`.*

---

## 📊 Reporte de Ejemplo

Puedes visualizar la estructura del reporte generado abriendo el archivo incluido en el repositorio:
📁 `reports/Reporte_Ejemplo_Auditoria_AD.html`

---

## 🔒 Seguridad y Garantía de Solo Lectura

* **100% Read-Only:** Este script **únicamente realiza consultas LDAP y diagnósticos de lectura**. No altera atributos, no deshabilita usuarios, no modifica directivas de grupo (GPOs) ni escribe en la base de datos `ntds.dit`.
* **Sin telemetría ni llamadas externas:** Toda la información recolectada permanece estrictamente en tu máquina local.

---

## 💼 Servicios Profesionales & Remediación

¿Ejecutaste el diagnóstico y encontraste hallazgos críticos en tu infraestructura?

Ofrezco servicios de consultoría especializada independiente para empresas en Colombia y remoto:
* **Doble Rotación Segura de `krbtgt`:** Ejecución programada sin impacto en servicios en producción.
* **Migración a gMSA (Group Managed Service Accounts):** Eliminación de contraseñas fijas en tareas programadas, IIS y servicios SQL.
* **Implementación de Windows LAPS Nativo:** Despliegue en estaciones y servidores mediante GPO o Intune.
* **Modernización y Migración de Domain Controllers:** Reemplazo de servidores EOL (2008/2012) a versiones vigentes (2022/2025).
* **Saneamiento y Hardening Integral:** Limpieza controlada de Active Directory bajo estándares CIS Benchmarks y NIST.

**Contacto:**
* 👤 **Ing. Ricardo Ospina Franco** (Especialista en Infraestructura TI & Sysadmin | +12 años de experiencia)
* 📧 **Email:** [rof.ospina@gmail.com](mailto:rof.ospina@gmail.com)
* 📱 **WhatsApp:** [+57 318 375 8111](https://wa.me/573183758111)
* 🌐 **LinkedIn:** [linkedin.com/in/ricardo-ospina-f](https://www.linkedin.com/in/ricardo-ospina-f)

---

## 📄 Licencia
Este proyecto está bajo la Licencia [MIT](LICENSE).
