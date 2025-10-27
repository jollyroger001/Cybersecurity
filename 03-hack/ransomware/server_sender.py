import socket

HOST = '0.0.0.0'  # Ascolta su tutte le interfacce
PORT = 5001       # Porta arbitraria

filename = 'plain.txt'  # File da inviare

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] In ascolto su {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"[+] Connessione da {addr}")
        with open(filename, 'rb') as f:
            data = f.read()
            conn.sendall(data)
        print("[+] File inviato con successo.")

