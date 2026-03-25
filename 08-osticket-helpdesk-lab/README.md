# Project 08 - osTicket Helpdesk Lab & Connection Monitor

## Overview
This project has two parts. Part 1 covers the installation and 
configuration of osTicket on Ubuntu Server as a helpdesk ticketing 
system. Part 2 covers building a Python based network intrusion 
detection tool with a live web dashboard.

## Part 1 - osTicket Helpdesk Setup
- Installed LAMP stack (Linux, Apache, MySQL, PHP) on Ubuntu Server
- Deployed osTicket helpdesk ticketing system
- Configured departments, SLA plans and help topics
- Set up automated email responses

## Part 2 - Connection Monitor (Python Security Tool)
Built a real time network security monitoring tool from scratch that detects:
- ARP spoofing and Man-in-the-Middle attacks
- Port scanning and reconnaissance attempts
- SSL stripping attacks
- SQL injection, command injection, XSS and webshell attempts
- New server and client connections

## Features
- Live web dashboard at port 9999 showing all alerts in real time
- Email alerts sent instantly when an attack is detected
- All alerts saved permanently to a log file
- 22 attack signatures built in

## Technologies Used
- Python 3, Scapy, Psutil
- Ubuntu Server 24.04 LTS
- Apache2, MySQL, PHP
- VMware Workstation
- Nmap and Zenmap for testing

## Screenshots
- 01_monitor_started - Script startup showing all modules active
- 02_dashboard_clean - Live dashboard before any attacks
- 03_attack_detected_terminal - Port scan detected in real time
- 04_dashboard_alerts - Dashboard showing 30 alerts captured
- 05_log_file - Full log file showing all detected events

## Status
Complete
