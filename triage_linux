#!/bin/bash
# =======================================================================================
# SCRIPT DE TRIAGE FORENSE
# Fecha: $(date)
# =======================================================================================

# 1. PREPARACIÓN DEL ENTORNO
# ---------------------------------------------------------------------------------------
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
HOSTNAME=$(hostname)
OUTPUT_DIR="/tmp/${CASE_ID}_${HOSTNAME}" # CAMBIAR ESTO A UN PUNTO DE MONTAJE EXTERNO SI ES POSIBLE
mkdir -p $OUTPUT_DIR
exec > >(tee -a ${OUTPUT_DIR}/triage_log.txt) 2>&1

echo "[*] Iniciando Triage Forense en $HOSTNAME a las $(date)"
echo "[*] Directorio de salida: $OUTPUT_DIR"
echo "[*] Hash inicial del script:"
sha256sum $0

# Función de ayuda para separar secciones
function log_section {
    echo ""
    echo "====================================================================="
    echo "[*] RECOLECTANDO: $1"
    echo "====================================================================="
}

# 2. INFORMACIÓN DEL SISTEMA Y FECHA (Contexto Base)
# ---------------------------------------------------------------------------------------
log_section "Información del Sistema"
date -u > $OUTPUT_DIR/system_date_utc.txt
uptime > $OUTPUT_DIR/system_uptime.txt
uname -a > $OUTPUT_DIR/system_uname.txt
cat /etc/*release > $OUTPUT_DIR/system_release.txt
# Verificar si estamos en GCP (Metadata)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/ -r > $OUTPUT_DIR/gcp_metadata.txt 2>/dev/null

# 3. CONEXIONES DE RED (Alta Volatilidad - CRÍTICO PARA MINERS)
# ---------------------------------------------------------------------------------------
# Buscamos conexiones a puertos de pools conocidos (3333, 4444, 8080, etc.) o IPs raras
log_section "Conexiones de Red Activas"
ss -antup > $OUTPUT_DIR/network_ss.txt
netstat -antup > $OUTPUT_DIR/network_netstat.txt
# Tabla de rutas y ARP (para ver si hay movimiento lateral)
route -n > $OUTPUT_DIR/network_route.txt
arp -a > $OUTPUT_DIR/network_arp.txt
# Puertos en escucha
lsof -i -P -n | grep LISTEN > $OUTPUT_DIR/network_listening.txt

# 4. PROCESOS Y MEMORIA (Alta Volatilidad)
# ---------------------------------------------------------------------------------------
log_section "Procesos en Ejecución"
# Snapshot completo de procesos
ps auxwwf > $OUTPUT_DIR/process_ps_tree.txt
ps -efM > $OUTPUT_DIR/process_ps_security_context.txt

# Buscar binarios eliminados que siguen corriendo (Táctica común de malware)
log_section "Binarios Eliminados en Ejecución (Fileless/Deleted)"
ls -alR /proc/*/exe 2>/dev/null | grep "(deleted)" > $OUTPUT_DIR/process_deleted_binaries.txt

# Volcar variables de entorno de procesos sospechosos (pueden contener keys o config de pools)
log_section "Variables de Entorno (Muestra global)"
for pid in $(ps -ef | awk '{print $2}'); do
    if [ -f /proc/$pid/environ ]; then
        echo "PID: $pid" >> $OUTPUT_DIR/process_environ.txt
        xargs -0 < /proc/$pid/environ >> $OUTPUT_DIR/process_environ.txt 2>/dev/null
        echo "----------------" >> $OUTPUT_DIR/process_environ.txt
    fi
done

# 5. RECURSOS ESPECÍFICOS DE IA (GPU/CPU) - EL "SMOKING GUN"
# ---------------------------------------------------------------------------------------
# Los mineros en máquinas de IA atacan la GPU.
log_section "Estado de GPU (NVIDIA-SMI)"
if command -v nvidia-smi &> /dev/null; then
    # Estado actual
    nvidia-smi > $OUTPUT_DIR/gpu_status.txt
    # Procesos usando GPU (Compute Apps)
    nvidia-smi pmon -c 5 > $OUTPUT_DIR/gpu_processes.txt
    # Consulta detallada para ver consumo de energía anómalo
    nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,pstate,pcie.link.gen.max,pcie.link.gen.current,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.free,memory.used --format=csv > $OUTPUT_DIR/gpu_detailed_query.csv
else
    echo "No se detectó nvidia-smi (¿No es instancia GPU o drivers eliminados?)" > $OUTPUT_DIR/gpu_missing.txt
fi

log_section "Uso de CPU (Top threads)"
top -b -n 1 > $OUTPUT_DIR/cpu_top.txt
mpstat -P ALL 1 5 > $OUTPUT_DIR/cpu_mpstat.txt

# 6. PERSISTENCIA (Donde se esconden para reiniciar)
# ---------------------------------------------------------------------------------------
log_section "Mecanismos de Persistencia"
# Cron jobs (Usuario y Sistema)
cat /etc/crontab > $OUTPUT_DIR/persistence_crontab_system.txt
ls -la /etc/cron.* > $OUTPUT_DIR/persistence_cron_dirs.txt
ls -la /var/spool/cron/crontabs/ > $OUTPUT_DIR/persistence_user_crons.txt
# Copiar contenidos de crons de usuarios
head -n 100 /var/spool/cron/crontabs/* > $OUTPUT_DIR/persistence_user_crons_content.txt 2>/dev/null

# Systemd Services (Buscar modificaciones recientes)
find /etc/systemd/system -type f -mtime -7 -exec ls -l {} \; > $OUTPUT_DIR/persistence_systemd_recent.txt
systemctl list-units --type=service --state=running > $OUTPUT_DIR/persistence_services_running.txt

# Scripts de inicio legacy
cat /etc/rc.local > $OUTPUT_DIR/persistence_rc_local.txt 2>/dev/null

# Claves SSH (Técnica común en Cloud para mantener acceso)
log_section "Claves SSH Autorizadas (Buscar keys desconocidas)"
cat /root/.ssh/authorized_keys > $OUTPUT_DIR/ssh_root_keys.txt 2>/dev/null
grep -r "ssh-rsa" /home/*/.ssh/authorized_keys > $OUTPUT_DIR/ssh_home_keys.txt 2>/dev/null

# 7. ARCHIVOS SOSPECHOSOS Y LOGS
# ---------------------------------------------------------------------------------------
log_section "Búsqueda de Archivos Sospechosos"
# Archivos ocultos o scripts en directorios temporales (Típico de droppers)
ls -alt /tmp /var/tmp /dev/shm > $OUTPUT_DIR/files_temp_dirs.txt

# Buscar patrones comunes de mineros (xmrig, stratum, monero, wallet addresses)
# NOTA: Esto puede tardar, limitamos a /var/log y /tmp
grep -rE "xmrig|stratum+tcp|minerd|monero|nanopool|cryptonight" /var/log /tmp /etc > $OUTPUT_DIR/grep_miner_keywords.txt 2>/dev/null

log_section "Recolección de Logs Críticos"
# Copia segura de logs
cp /var/log/auth.log $OUTPUT_DIR/log_auth.log 2>/dev/null # Debian/Ubuntu
cp /var/log/secure $OUTPUT_DIR/log_secure.log 2>/dev/null  # RHEL/CentOS
cp /var/log/syslog $OUTPUT_DIR/log_syslog.log 2>/dev/null
cp /var/log/messages $OUTPUT_DIR/log_messages.log 2>/dev/null
dmesg > $OUTPUT_DIR/log_dmesg.txt

# Audit logs si existe auditd
if command -v ausearch &> /dev/null; then
    ausearch -m EXECVE -ts recent > $OUTPUT_DIR/log_audit_exec.txt
fi

# Historial de comandos (Bash history)
log_section "Historial Bash (Root y Usuarios)"
cat /root/.bash_history > $OUTPUT_DIR/history_root.txt 2>/dev/null
cat /home/*/.bash_history > $OUTPUT_DIR/history_users.txt 2>/dev/null

# 8. HASHING Y EMPAQUETADO (Cadena de Custodia)
# ---------------------------------------------------------------------------------------
log_section "Finalizando y Hashing"
# Crear lista de archivos recolectados
find $OUTPUT_DIR -type f > $OUTPUT_DIR/file_inventory.txt

# Calcular hashes de toda la evidencia
sha256sum $OUTPUT_DIR/* > $OUTPUT_DIR/SHA256SUMS.txt

echo "[*] Triage completado. Comprimiendo evidencia..."
tar -czvf ${OUTPUT_DIR}.tar.gz -C $(dirname $OUTPUT_DIR) $(basename $OUTPUT_DIR)

echo "[*] Hash del paquete final:"
sha256sum ${OUTPUT_DIR}.tar.gz

echo "[SUCCESS] La evidencia se encuentra en: ${OUTPUT_DIR}.tar.gz"
echo "IMPORTANTE: Descarga este archivo AHORA y sácalo de la red GCP."
