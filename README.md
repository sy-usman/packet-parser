# Dialysis Machine Packet Parser
A Python tool to decode raw data packets from medical dialysis machines into human-readable reports.

## What It Does

- 🔍 Reads hex data from dialysis machines
- 📦 Breaks down complex packets into understandable parts
- 🚨 Shows machine status (alarms, treatments, errors)
- 📊 Displays medical measurements and logs
- 🛠️ Handles special data formatting quirks

## Key Features

- Header analysis (machine ID, serial number, command type)
- Real-time status monitoring
- Treatment log decoding with timestamps
- Medical measurement extraction (blood flow, pressure, etc.)
- Error checking and data validation

=== PACKET HEADER ===
Identifier: 0x40 ('@')
Source Device: Dialysis Machine (International)
Serial Number: M2-2155109
Current Command: Log Data (0x0005)

=== MACHINE STATUS ===
[!] Alarm Active
[ ] Treatment Running
[✔] Standby Mode
No Errors Detected

=== PATIENT INFO ===
ID: PX-489230 (Temporary)

--- TREATMENT LOGS ---
12:45:00 - Blood Flow: 300 mL/min → 150 mL/min
13:00:00 - Pressure Alert (Venous Line)
13:15:00 - UF Completed: 1500 mL
