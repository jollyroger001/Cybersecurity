import socket
import sys
import os

if len(sys.argv) != 2:
    print("Uso: python3 server_sender.py <nome_file>")
    sys.exit(1)

filename = sys.argv[1]

if not os.path.isfile(filename):
    print(f"Errore: il file '{filename}' non esiste.")
    sys.exit(1)

HOST = '0.0.0.0'
PORT = 5001

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] In ascolto su {HOST}:{PORT} per inviare '{filename}'...")

    conn, addr = s.accept()
    with conn:
        print(f"[+] Connessione da {addr}")
        # Invia prima il nome del file
        conn.sendall(filename.encode() + b'\n')
        with open(filename, 'rb') as f:
            data = f.read()
            conn.sendall(data)
        print("[+] File inviato con successo.")
