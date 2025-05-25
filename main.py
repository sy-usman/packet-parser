from typing import Dict, List, Tuple

class ByteUnescaper:
    @staticmethod
    def unescape(data: bytes) -> bytes:
        """Handle M2 escape sequence conversions"""
        unescaped = []
        i = 0
        while i < len(data):
            if data[i] == 0x10 and i + 1 < len(data):
                esc = data[i+1]
                if esc == 0x10:
                    unescaped.append(0x10)
                    i += 2
                elif esc == 0x12:
                    unescaped.append(0x02)
                    i += 2
                elif esc == 0x13:
                    unescaped.append(0x03)
                    i += 2
                else:
                    unescaped.append(data[i])
                    i += 1
            else:
                unescaped.append(data[i])
                i += 1
        return bytes(unescaped)

class HeaderParser:
    """Parse 26-byte command header structure"""
    HEADER_SIZE = 26
    
    def __init__(self, data: bytes):
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Invalid header length")
        
        self.identifier = data[0]
        self.header_size = data[1]
        self.source_device_id = data[2]
        self.source_version = data[3]
        self.serial_number = self._parse_serial(data[4:20])
        self.sequence_number = int.from_bytes(data[20:22], 'big')
        self.command_id = int.from_bytes(data[22:24], 'big')
        self.data_size = int.from_bytes(data[24:26], 'big')

    def _parse_serial(self, serial_bytes: bytes) -> str:
        """Parse Unicode serial number from 16 bytes"""
        return ''.join(
            chr(int.from_bytes(serial_bytes[i:i+2], 'big')) 
            for i in range(2, 16, 2)  # Skip first 2 dummy bytes
        ).strip('\x00')

class StatusParser:
    """Parse 2-byte status field with bitwise operations"""
    @staticmethod
    def parse(status_bytes: bytes) -> Dict:
        if len(status_bytes) < 2:
            return {}
            
        return {
            'raw': status_bytes[0],
            'log_present': bool(status_bytes[0] & 0x80),
            'post_info': bool(status_bytes[0] & 0x40),
            'info_active': bool(status_bytes[0] & 0x20),
            'post_alarm': bool(status_bytes[0] & 0x10),
            'alarm_active': bool(status_bytes[0] & 0x08),
            'standby_mode': bool(status_bytes[0] & 0x04),
            'cleaning_mode': bool(status_bytes[0] & 0x02),
            'treatment_active': bool(status_bytes[0] & 0x01),
            'end_code': status_bytes[1] & 0x0F
        }

class LogDecoder:
    """Decode log data structure with BCD timestamp parsing"""
    @staticmethod
    def _bcd_to_int(bcd: int) -> int:
        return (bcd >> 4) * 10 + (bcd & 0x0F)

    def decode(self, data: bytes) -> List[Dict]:
        entries = []
        pos = 0
        while pos + 34 <= len(data):
            entry = {
                'sequence': int.from_bytes(data[pos:pos+2], 'big'),
                'code_id': data[pos+2:pos+4].hex().upper(),
                'timestamp': self._parse_timestamp(data[pos+4:pos+12]),
                'body_detected': int.from_bytes(data[pos+12:pos+14], 'big'),
                'decimal_pos': int.from_bytes(data[pos+14:pos+16], 'big'),
                'before': int.from_bytes(data[pos+16:pos+20], 'big', signed=True),
                'after': int.from_bytes(data[pos+20:pos+24], 'big', signed=True),
                'ext1': int.from_bytes(data[pos+24:pos+28], 'big', signed=True),
                'ext2': int.from_bytes(data[pos+28:pos+32], 'big', signed=True),
                'reservation': int.from_bytes(data[pos+32:pos+34], 'big')
            }
            entries.append(entry)
            pos += 34
        return entries

    def _parse_timestamp(self, data: bytes) -> str:
        return (
            f"{self._bcd_to_int(data[0])*100 + self._bcd_to_int(data[1])}-"
            f"{self._bcd_to_int(data[2]):02}-"
            f"{self._bcd_to_int(data[3]):02} "
            f"{self._bcd_to_int(data[4]):02}:"
            f"{self._bcd_to_int(data[5]):02}:"
            f"{self._bcd_to_int(data[6])*100 + self._bcd_to_int(data[7]):04}"
        )

class MonitorDecoder:
    """Decode monitor data using BMR tag mappings"""
    TAG_MAP = {
        0x0000: "Not Used",
        0x0001: "Mode",
        0x0002: "Elapsed time",
        0x0003: "Elapsed time (ECUM)",
        0x0004: "Time Remaining (UF)",
        0x0005: "Time Remaining (Tx.)",
        0x0006: "UF Vol.",
        0x0007: "UF Rate",
        0x0008: "Total Treated Blood Vol.",
        0x0009: "Blood Flow Rate",
        0x000A: "HP Vol",
        0x000B: "HP Rate",
        0x000C: "Venous Press.",
        0x000D: "Dialysate Press.",
        0x000E: "TMP",
        0x000F: "Dialyser Inlet Press.",
        0x0010: "Press. Loss",
        0x0012: "dBV",
        0x0013: "Bic. Condo.",
        0x0016: "Dialysate Temp.",
        0x0019: "Water Press. (Upper)",
        0x001A: "Water Press. (Lower)",
        0x0020: "Treatment Mode",
        0x0028: "Venous Press. Limit (Upper)",
        0x002C: "TMP Limit (Upper)",
        0x0032: "dBV drop 1 Limit",
        0x0039: "Total Condo. Limit (Upper)",
        0x003A: "Total Condo. Limit (Lower)",
        0x003F: "Blood Leak Limit",
        0x0043: "Initial UFK Limit (Lower)",
        0x0044: "UFK Drop Limit",
        0x0047: "Substitution Fluid Rate Set Value",
        0x004D: "Filtration Rate",
        0x005B: "Systolic Press.",
        0x005C: "Diastolic Press.",
        0x005D: "Mean Arterial Press.",
        0x005E: "Pulse Rate",
        0x005F: "Body Temp.",
        0x0062: "Art. Press.",
    }

    def decode(self, data: bytes) -> List[Tuple[int, str, int]]:
        tags = []
        for i in range(0, len(data), 4):
            if i+4 > len(data):
                break
            tag_id = int.from_bytes(data[i:i+2], 'big')
            value = int.from_bytes(data[i+2:i+4], 'big', signed=True)
            desc = self.TAG_MAP.get(tag_id, f"Not Used (0x{tag_id:04X})")
            tags.append((tag_id, desc, value))
        return tags

class PacketProcessor:
    """Main packet processing class with validation and parsing pipeline"""
    def __init__(self):
        self.monitor_decoder = MonitorDecoder()
        self.log_decoder = LogDecoder()

    def process(self, raw_hex: str) -> str:
        try:
            # Validate and preprocess
            raw_bytes = bytes.fromhex(raw_hex.replace(' ', ''))
            if raw_bytes[0] != 0x02 or raw_bytes[-1] != 0x03:
                return "Invalid packet delimiters"
            
            # Unescape and validate checksum
            processed = ByteUnescaper.unescape(raw_bytes[1:-1])
            if sum(processed[:-1]) & 0xFF != processed[-1]:
                return "Checksum mismatch"
            
            return self._parse_packet(processed[:-1])
        except Exception as e:
            return f"Processing error: {str(e)}"

    def _parse_packet(self, data: bytes) -> str:
        """Main parsing workflow"""
        output = []
        
        # Header section
        header = HeaderParser(data[:26])
        output.append("=== PACKET HEADER ===")
        output.extend([
            f"Identifier: 0x{header.identifier:02X} ('@')",
            f"Header Size: {header.header_size} bytes",
            f"Source Device ID: 0x{header.source_device_id:02X} ('E') ? Dialysis machine (international)",
            f"Device Version: {header.source_version} (Communication spec version)",
            f"Serial Number: {header.serial_number}",
            f"Sequence Number: {header.sequence_number}",
            self._format_command_id(header.command_id),
            f"Declared Data Size: {header.data_size} bytes\n",
        ])

        # Status section
        status = StatusParser.parse(data[26:28])
        output.append("=== STATUS ===")
        output.extend([
            f"Raw Status Byte: 0x{status['raw']:02X}",
            "- Log Present: " + ("Yes" if status['log_present'] else "No"),
            "- Device States:",
            f"   Treatment Active: {status['treatment_active']}",
            f"   Cleaning Mode: {status['cleaning_mode']}",
            f"   Standby Mode: {status['standby_mode']}",
            f"   Alarm Active: {status['alarm_active']}",
            f"   Post-Alarm: {status['post_alarm']}",
            f"   Info Active: {status['info_active']}",
            f"   Post-Info: {status['post_info']}",
            f"End Code: {status['end_code']} ? Normal completion\n",
        ])

        # Patient ID section
        patient_id = data[28:36].decode('ascii', errors='ignore').strip('\x00')
        output.append("=== PATIENT ID ===")
        output.append(f"Patient ID (ASCII, 8 bytes): {patient_id}\n")

        # Data section
        output.append("--- Packet Data ---")
        payload = data[36:36+header.data_size]
        
        if header.command_id == 0x0005:  # Log data
            self._process_log(output, header, payload)
        elif header.command_id in [0x0002, 0x0102]:  # Monitor data
            self._process_monitor(output, header, payload)
        else:
            output.append(f"Unknown packet type: 0x{header.command_id:04X}")

        return '\n'.join(output)

    def _format_command_id(self, command_id: int) -> str:
        """Format command ID with description"""
        descriptions = {
            0x0001: "Status",
            0x0002: "Monitor Data",
            0x0005: "Log Data",
            0x0102: "Unknown Command"
        }
        desc = descriptions.get(command_id, "Unknown Command")
        return f"Command ID: 0x{command_id:04X} ? {desc}"

    def _process_log(self, output: list, header: HeaderParser, payload: bytes):
        """Handle log data decoding"""
        try:
            logs = self.log_decoder.decode(payload)
            output.extend([
                "Type: Log",
                f"Device: E, Serial: {header.serial_number}, "
                f"Sequence: {header.sequence_number}, Command: 0x{header.command_id:04X}"
            ])
            for log in logs:
                output.extend([
                    f"Code ID: {log['code_id']}",
                    f"Timestamp: {log['timestamp']}",
                    f"Before: {log['before']}",
                    f"After: {log['after']}",
                    f"Extensions: [Ext1: {log['ext1']}, Ext2: {log['ext2']}]",
                    f"Body Detected: {log['body_detected']}\n"
                ])
        except Exception as e:
            output.append(f"Log decoding error: {str(e)}")

    def _process_monitor(self, output: list, header: HeaderParser, payload: bytes):
        """Handle monitor data decoding"""
        try:
            tags = self.monitor_decoder.decode(payload)
            output.extend([
                "Type: Monitor",
                f"Device: E, Serial: {header.serial_number}, "
                f"Sequence: {header.sequence_number}, Command: 0x{header.command_id:04X}",
                "Monitor Data:"
            ])
            for tag_id, desc, value in tags:
                output.append(f"   {desc} (0x{tag_id:04X}): {value}")
        except Exception as e:
            output.append(f"Monitor decoding error: {str(e)}")

# Example usage
if __name__ == "__main__":
    examples = {
        "Example1": (
            "02 40 1A 45 01 00 20 00 32 00 31 00 35 00 35 00 31 00 30 00 39 00 55 00 05 00 30 8C 00 00 00 00 00 00 "
            "00 00 00 00 01 00 00 49 30 20 25 05 09 19 25 00 10 12 00 10 12 00 00 00 10 13 00 00 00 00 00 00 04 "
            "00 00 00 00 00 05 00 00 00 00 00 06 00 00 00 00 00 07 AB 10 13 13 03"
        ),
        # Add other examples here following the same pattern
       "Example2": ("02 40 1A 45 01 00 20 00 32 00 31 00 35 00 35 00 31 00 30 00 39 00 7A 00 05 00 30 81 00 00 00 00 00 00"
                    "00 00 00 00 01 00 00 49 30 20 25 05 09 19 25 00 10 12 00 10 12 00 00 00 10 13 00 00 00 00 00 00 00 04"
                    "00 00 00 00 00 05 00 00 00 00 00 06 00 00 00 00 00 07 AB 10 13 2D 03"),
        "Example3": ("02 40 1A 45 01 00 20 00 32 00 31 00 35 00 35 00 31 00 30 00 39 00 B2 00 05 00 30 81 00 00 00 00 00 00"
                     "00 00 00 00 01 00 00 49 30 20 25 05 09 19 25 00 10 12 00 10 12 00 00 00 10 13 00 00 00 00 00 00 00 04"
                     "00 00 00 00 00 05 00 00 00 00 00 06 00 00 00 00 00 07 AB 10 13 65 03"),
        "Example4":("02 40 1A 45 01 00 20 00 32 00 31 00 35 00 35 00 31 00 30 00 39 00 56 00 10 12 01 68 04 00 00 00 00 00"
"00 00 00 00 00 01 00 82 00 10 12 00 00 00 10 13 00 00 00 04 00 F0 00 05 00 F0 00 06 00 00 00 07 00 00"
"00 08 00 00 00 09 00 00 00 0A 00 00 00 0B 00 00 00 0C FF 28 00 0D 00 01 00 0E FF 36 00 0F FF 16 00 10"
"10 FF EE 00 11 FF 1F 00 12 00 00 00 13 01 38 00 14 00 84 00 15 00 00 00 16 01 75 00 17 01 F4 00 18 00"
"00 00 19 00 33 00 1A 00 2C 00 1B 75 31 00 1C 00 00 00 1D 00 00 00 1E FE 8C 00 1F 00 00 00 20 00 00 00"
"21 00 64 00 22 00 19 00 23 00 25 00 24 01 F4 00 25 00 41 00 26 00 00 00 27 FF FF 00 28 01 F4 00 29 FE"
"D4 00 2A 01 F4 00 2B FE 0C 00 2C 80 00 00 2D 80 00 00 2E 10 12 DF 00 2F FE D4 00 30 80 00 00 31 80 00"
"00 32 00 00 00 33 FC 18 00 34 FF 38 00 37 01 47 00 38 01 28 00 39 00 8B 00 3A 00 7E 00 3B 00 00 00 3C"
"80 00 00 3D 01 9A 00 3E 01 2C 00 3F 00 05 00 40 80 00 00 41 80 00 00 42 4E 20 00 43 00 64 00 44 00 32"
"00 45 00 00 00 46 00 00 00 47 00 00 00 48 00 00 00 49 00 00 00 4A 00 00 00 4D 00 00 00 4F 00 00 00 50"
"FF FF 00 51 00 00 00 52 00 00 00 59 D8 F1 00 5A FF FF 00 5B 00 00 00 5C 00 00 00 5D 00 00 00 5E 00 00"
"00 5F 00 00 00 62 00 0B 00 63 01 2C 00 64 FE D4 00 65 FF FF 00 66 FF FF 00 67 FF FF 8A 03"),

"Example5":("02 40 1A 45 01 00 20 00 32 00 31 00 35 00 35 00 31 00 30 00 39 00 7B 00 10 12 01 68 01 00 00 00 00 00"
"00 00 00 00 00 01 00 14 00 10 12 00 04 00 10 13 00 00 00 04 00 EC 00 05 00 EC 00 06 00 01 00 07 00 19"
"00 08 00 07 00 09 01 3B 00 0A 00 00 00 0B 00 00 00 0C 00 20 00 0D 00 1A 00 0E FF E3 00 0F 00 2C 00 10"
"10 00 0F 00 11 00 26 00 12 00 00 00 13 01 37 00 14 00 84 00 15 00 00 00 16 01 73 00 17 01 F4 00 18 00"
"00 00 19 00 33 00 1A 00 2D 00 1B 75 31 00 1C 00 00 00 1D 00 00 00 1E FE 8C 00 1F 00 04 00 20 00 00 00"
"21 00 64 00 22 00 19 00 23 00 25 00 24 01 F4 00 25 01 3B 00 26 00 00 00 27 FF FF 00 28 00 5C 00 29 00"
"0A 00 2A 01 90 00 2B FE D4 00 2C 80 00 00 2D 80 00 00 2E 10 12 58 00 2F FF CE 00 30 01 F4 00 31 FF C4"
"00 32 00 00 00 33 FC 18 00 34 FF 38 00 37 01 47 00 38 01 28 00 39 00 8B 00 3A 00 7E 00 3B 00 00 00 3C"
"80 00 00 3D 01 7C 00 3E 01 68 00 3F 00 05 00 40 00 37 00 41 00 0A 00 42 4E 20 00 43 00 64 00 44 00 32"
"00 45 00 00 00 46 00 4A 00 47 00 00 00 48 00 00 00 49 00 00 00 4A 00 00 00 4D 00 19 00 4F 00 00 00 50"
"FF FF 00 51 00 00 00 52 00 00 00 59 D8 F1 00 5A FF FF 00 5B 00 00 00 5C 00 00 00 5D 00 00 00 5E 00 00"
"00 5F 00 00 00 62 00 10 12 00 63 00 47 00 64 FF BB 00 65 FF FF 00 66 FF FF 00 67 FF FF 7E 03")
        
    }

    processor = PacketProcessor()
    for name, packet in examples.items():
        print(f"\n{name} Output:")
        print(processor.process(packet))