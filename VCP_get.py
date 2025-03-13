import serial
import sys,struct,re

SERIAL_PORT = 'COM14'  
BAUD_RATE = 115200  


def extract_text(packet: bytes) -> str:
    try:
        # Decode packet assuming text messages are ASCII or UTF-8
        text = packet.decode(errors='ignore')

        # Extract readable text using regex (printable ASCII characters)
        message = re.findall(r'[\x20-\x7E]+', text)

        return ' '.join(message)
    except Exception as e:
        return f"Error: {e}"



def parse_crsf_packet(packet):
    # Convert bytes to a list of integers for easier processing
    data = list(packet)
    
    # Validate the header (first byte)
    if len(data) < 3:
        print("Invalid CRSF packet: Too short")
        return
    
    if data[0] != 0x08:
        print("Invalid CRSF header")
        return
    
    # Extract length (second byte)
    length = data[1]
    if length + 2 > len(data):
        print(f"Invalid packet length: {length}, actual size: {len(data)}")
        return
    
    payload = data[2:2+length]  # Extract payload
    crc = data[2+length]  # Extract CRC (last byte)
    
    print(f"Packet Length: {length}")
    print(f"Payload: {payload}")
    print(f"CRC: {crc}")
    
    if not payload:
        print("Empty payload, skipping parsing")
        return
    
    # Parsing known message types (simplified example)
    packet_type = payload[0] if len(payload) > 0 else None
    
    if packet_type == 0x16 and len(payload) >= 13:  # Example: GPS packet
        lat, lon, alt = struct.unpack('<iii', bytes(payload[1:13]))
        print(f"GPS Data - Lat: {lat}, Lon: {lon}, Alt: {alt}")
    elif packet_type == 0x14 and len(payload) >= 4:  # Link statistics
        rssi, snr, rf_mode = payload[1], payload[2], payload[3]
        print(f"Link Stats - RSSI: {rssi}, SNR: {snr}, RF Mode: {rf_mode}")
    elif b'!STAB' in packet:  # Flight mode detection
        mode_index = packet.index(b'!STAB')
        mode_name = packet[mode_index:mode_index + 6].decode(errors='ignore')
        print(f"Flight Mode: {mode_name}")
    else:
        print("Unknown or incomplete Packet Type")


def main():
    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1) as ser:
            while True:
                data = ser.readline()
                if data:
                    print(data)
                    #extract_text(data)
                    if b'!STAB' in data:  # Flight mode detection
                        print("flight mode: STAB")
                    elif b'!ALT' in data:  # Flight mode detection
                        print("flight mode: ALTH")
                    #parse_crsf_packet(data)
                    #print(data.rstrip().decode('utf-16'))

    except serial.SerialException as e:
        print(f"Error opening or using the serial port: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
