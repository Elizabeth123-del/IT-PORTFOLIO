# Project 05 — Linux Server Hardening

## Status
Completed — March 2026

## Overview
Hardened an Ubuntu Server 24.04 LTS virtual machine 
following security best practices and CIS Benchmark 
guidelines to simulate a production server environment.


### 1. System Updates
- Updated all packages and applied security patches
- Ensured system is running latest stable versions

### 2. User Management
- Created dedicated admin user (secadmin)
- Added secadmin to sudo group
- Verified user privileges
- Disabled root login via SSH

### 3. SSH Hardening
- Disabled root login (PermitRootLogin no)
- Disabled empty passwords (PermitEmptyPasswords no)
- Restarted SSH service to apply changes

### 4. Firewall Configuration (UFW)
- Enabled UFW firewall
- Allowed SSH on port 22
- Allowed HTTP on port 80
- Allowed HTTPS on port 443
- All other ports denied by default

### 5. Brute Force Protection (fail2ban)
- Installed and enabled fail2ban
- Configured SSH jail
- Set maxretry to 3 failed attempts
- Set bantime to 3600 seconds (1 hour)
- Set findtime to 600 seconds (10 minutes)
- Verified sshd jail is active and monitoring

### 6. Automated Backup
- Created daily cron job
- Backs up /etc and /home directories
- Logs backup completion to /var/log/backup.log

## Tools Used
- Ubuntu Server 24.04 LTS
- UFW (Uncomplicated Firewall)
- fail2ban
- nano text editor
- systemctl
- cron

## Skills Demonstrated
- Linux command line administration
- SSH hardening and configuration
- Firewall rule management
- Brute force attack prevention
- Automated backup scripting
- Security service monitoring
- Linux user and permission management

## Hardening Checklist
All completed steps are documented in the 
hardening-checklist.md file in this folder.

## Screenshots
All screenshots are in the screenshots folder above.
