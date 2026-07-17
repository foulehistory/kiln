@echo off
wsl -d Ubuntu -u root -e /mnt/e/kiln/bin/kiln-launch.sh kiln-compose %*
