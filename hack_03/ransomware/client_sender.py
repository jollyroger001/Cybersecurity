import socket

SERVER_IP = '192.168.15.132'  # IP della macchina Kali
PORT = 5001
output_file = 'received_plain.txt'  # Nome del file da salvare

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, PORT))
    print(f"[+] Connesso a {SERVER_IP}:{PORT}")
    
    with open(output_file, 'wb') as f:
        while True:
            data = s.recv(1024)
            if not data:
                break
            f.write(data)
    print(f"[+] File ricevuto e salvato come {output_file}")
