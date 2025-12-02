# 📋 TODO - System Scripts Repository

**Autor:** Seb (pentester@netcuter.com)  
**Data:** 2025-11-28  
**Cel:** Plan rozwoju kolekcji skryptów systemowych

---

## 📁 AKTUALNA STRUKTURA (do reorganizacji):

```
system/
├── README.md
└── [skrypty bash/python]
```

## 🎯 DOCELOWA STRUKTURA:

```
system/
├── README.md
├── install.sh              # Instalator wszystkich skryptów
├── network/
│   ├── ip_scanner.sh       # Skanowanie sieci lokalnej
│   ├── port_monitor.sh     # Monitorowanie portów
│   ├── wifi_analyzer.py    # Analiza WiFi
│   └── bandwidth_test.sh   # Test przepustowości
├── security/
│   ├── log_analyzer.sh     # Analiza logów bezpieczeństwa
│   ├── firewall_rules.sh   # Zarządzanie firewallem
│   ├── ssh_hardening.sh    # Hardening SSH
│   └── fail2ban_setup.sh   # Konfiguracja fail2ban
├── backup/
│   ├── rsync_backup.sh     # Backup przez rsync
│   ├── db_backup.py        # Backup baz danych
│   └── config_backup.sh    # Backup konfiguracji
├── monitoring/
│   ├── system_health.sh    # Ogólny stan systemu
│   ├── disk_alert.sh       # Alert przy pełnym dysku
│   ├── process_monitor.py  # Monitoring procesów
│   └── lmstudio_health.sh  # Monitoring LM Studio serwerów
└── utils/
    ├── cleanup.sh          # Czyszczenie systemu
    ├── update_all.sh       # Aktualizacja wszystkiego
    └── dotfiles_sync.sh    # Synchronizacja dotfiles
```

---

## 📝 TODO - PRIORYTET WYSOKI:

### TODO-S1: Reorganizacja katalogów
```bash
ZADANIE: Przenieś istniejące skrypty do odpowiednich podkatalogów
KROKI:
1. mkdir -p network security backup monitoring utils
2. Przejrzyj każdy skrypt i zdecyduj gdzie pasuje
3. git mv stary_plik.sh nowy_katalog/
4. Zaktualizuj README.md z nową strukturą
```

### TODO-S2: Skrypt monitoringu LM Studio
```bash
PLIK: monitoring/lmstudio_health.sh
OPIS: Monitoruj serwery LM Studio używane w projekcie local-custom-llm

#!/bin/bash
# LM Studio Health Monitor
# Użycie: ./lmstudio_health.sh

SERVERS=(
    "172.22.48.1:8087"      # Laptop - Granite
    "192.168.137.1:8087"    # Desktop - Gemma
    "10.122.194.239:8087"   # Backup
)

LOG_FILE="/var/log/lmstudio_health.log"

check_server() {
    local server=$1
    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 "http://$server/v1/models")
    
    if [ "$response" == "200" ]; then
        echo "[$(date)] ✅ $server - OK" >> "$LOG_FILE"
        return 0
    else
        echo "[$(date)] ❌ $server - FAILED (HTTP $response)" >> "$LOG_FILE"
        # Opcjonalnie: wyślij alert
        return 1
    fi
}

main() {
    echo "=== LM Studio Health Check ===" >> "$LOG_FILE"
    for server in "${SERVERS[@]}"; do
        check_server "$server"
    done
}

main
```

### TODO-S3: Skrypt backup konfiguracji
```bash
PLIK: backup/config_backup.sh
OPIS: Backup ważnych konfiguracji projektu

#!/bin/bash
# Config Backup Script

BACKUP_DIR="/backup/configs/$(date +%Y-%m-%d)"
mkdir -p "$BACKUP_DIR"

# Lista katalogów do backupu
CONFIGS=(
    "$HOME/.lmstudio"
    "$HOME/Local-LLM-with-voice-support/backend/config"
    "/etc/nginx"
)

for config in "${CONFIGS[@]}"; do
    if [ -d "$config" ]; then
        name=$(basename "$config")
        tar -czf "$BACKUP_DIR/${name}.tar.gz" "$config" 2>/dev/null
        echo "✅ Backup: $config"
    fi
done

echo "Backup completed: $BACKUP_DIR"
```

---

## 📝 TODO - PRIORYTET ŚREDNI:

### TODO-S4: Instalator globalny
```bash
PLIK: install.sh
OPIS: Instaluj wszystkie skrypty do /usr/local/bin

#!/bin/bash
# System Scripts Installer

INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(dirname "$0")"

install_scripts() {
    for dir in network security backup monitoring utils; do
        if [ -d "$SCRIPT_DIR/$dir" ]; then
            for script in "$SCRIPT_DIR/$dir"/*.sh; do
                [ -f "$script" ] || continue
                name=$(basename "$script" .sh)
                sudo cp "$script" "$INSTALL_DIR/nc-$name"
                sudo chmod +x "$INSTALL_DIR/nc-$name"
                echo "✅ Installed: nc-$name"
            done
        fi
    done
}

install_scripts
echo "Done! Scripts available with 'nc-' prefix"
```

### TODO-S5: README z dokumentacją
```markdown
PLIK: README.md
ZAWARTOŚĆ:
- Opis każdego skryptu
- Wymagania (bash, python3, curl, etc.)
- Przykłady użycia
- Konfiguracja (zmienne środowiskowe)
```

### TODO-S6: Systemd timers dla automatyzacji
```bash
PLIK: systemd/lmstudio-health.timer
OPIS: Uruchamiaj health check co 5 minut

[Unit]
Description=LM Studio Health Check Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

---

## 📝 TODO - PRIORYTET NISKI:

### TODO-S7: Testy jednostkowe
```bash
PLIK: tests/test_scripts.sh
OPIS: Podstawowe testy czy skrypty działają
```

### TODO-S8: Integracja z Zabbix/Prometheus
```
OPIS: Eksportuj metryki do systemów monitoringu
```

---

## 🛠️ INSTRUKCJE DLA AI:

1. **Przed edycją** - przeczytaj istniejący kod
2. **Shebang** - zawsze `#!/bin/bash` lub `#!/usr/bin/env python3`
3. **Komentarze** - po polsku lub angielsku
4. **Testuj** - każdy skrypt przed commitem
5. **Logi** - używaj standardowych ścieżek `/var/log/`

**Format commit:**
```
[kategoria] Krótki opis

Szczegóły zmian.
```

---

 Done!
