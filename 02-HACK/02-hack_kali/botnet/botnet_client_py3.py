#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys

def connect_to_server(server_ip: str, server_port: int, bufsize: int = 4096, timeout: float = 10.0) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        print(f"Connessione a {server_ip} porta {server_port} ...")
        sock.connect((server_ip, server_port))
        print("Connesso. Scrivi 'exit' per chiudere.\n")

        while True:
            try:
                message = input("Messaggio> ").strip()
            except EOFError:
                print("\nEOF ricevuto. Chiusura.")
                break
            except KeyboardInterrupt:
                print("\nInterrotto da tastiera. Chiusura.")
                break

            if not message:
                continue
            if message.lower() == "exit":
                print("Chiusura connessione...")
                break

            # Invia bytes (UTF-8)
            wire = message.encode("utf-8")
            sock.sendall(wire)

            # Ricevi la risposta (il server fa echo in maiuscolo)
            try:
                data = sock.recv(bufsize)
            except socket.timeout:
                print("(timeout in ricezione)")
                continue

            if not data:
                print("Connessione chiusa dal server.")
                break

            try:
                print("Risposta:", data.decode("utf-8"))
            except UnicodeDecodeError:
                print("Risposta (bytes):", data)

    except KeyboardInterrupt:
        print("\nInterrotto da tastiera. Chiusura.")
    except Exception as e:
        print(f"Errore: {e}")
        sys.exit(1)
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("Connessione chiusa.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 client.py <server_ip> <server_port>")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Errore: la porta deve essere un intero.")
        sys.exit(1)

    connect_to_server(ip, port)
