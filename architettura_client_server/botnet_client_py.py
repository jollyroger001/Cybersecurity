#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
client_commented.py

Versione del client TCP con commenti dettagliati inline che spiegano
i metodi e le chiamate principali usate nel programma.

Comportamento:
 - apre una socket TCP verso server_ip:server_port
 - legge righe dall'utente (input), le invia al server (sendall)
 - attende una risposta (recv) e la mostra decodificata in UTF-8
 - comandi utili dall'utente: "exit" per chiudere il client
"""

import socket        # libreria standard per socket di rete (RFC IP/TCP/UDP)
import sys           # usata per leggere argv e terminare con sys.exit()

def connect_to_server(server_ip: str, server_port: int, bufsize: int = 4096, timeout: float = 10.0) -> None:
    """
    Connette il client al server TCP e gestisce un semplice loop di invio/ricezione.

    Parametri:
      server_ip: indirizzo IPv4 o hostname del server (stringa)
      server_port: porta TCP del server (intero)
      bufsize: dimensione massima in byte del buffer per la recv()
      timeout: timeout (in secondi) usato sia per sock.settimeout() che
               come timeout generale di operazioni bloccanti sulla socket

    Nota sui metodi principali usati:
      - socket.socket(socket.AF_INET, socket.SOCK_STREAM):
          crea una socket IPv4 (AF_INET) orientata alla connessione (SOCK_STREAM = TCP).
      - settimeout(seconds):
          imposta un timeout sulle operazioni di I/O sulla socket; provocherà
          socket.timeout se un'operazione bloccante non completa entro il tempo.
      - connect((host, port)):
          avvia il three-way handshake TCP verso host:port. Blocca (o lancia eccezione)
          fino a riuscita connessione o errore.
      - sendall(bytes):
          invia tutti i byte passati; blocca finché tutti i byte non sono stati inviati
          (o lancia un'eccezione). A differenza di send(), garantisce che venga
          tentato l'invio completo del buffer.
      - recv(bufsize):
          legge fino a bufsize byte dalla socket; ritorna b'' se il peer chiude
          la connessione (EOF). Ritorna bytes che vanno quindi decodificati da UTF-8.
      - close():
          chiude la socket (rilascia risorse di sistema).
    """

    # Creazione della socket TCP IPv4.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Impostiamo un timeout sulle operazioni di I/O della socket.
        # Questo evita che recv/connect rimangano bloccati indefinitamente.
        sock.settimeout(timeout)

        # Stampa di stato all'utente.
        print(f"Connessione a {server_ip} porta {server_port} ...")

        # Connessione al server remoto (blocking o con timeout).
        # Se fallisce, verrà sollevata un'eccezione (es. socket.timeout, OSError).
        sock.connect((server_ip, server_port))
        print("Connesso. Scrivi 'exit' per chiudere.\n")

        # Loop principale di invio/ricezione:
        # finché l'utente non scrive 'exit' o non si verifica un errore.
        while True:
            try:
                # input() legge una linea da stdin (prompt). Può sollevare:
                # - EOFError: se riceve EOF (Ctrl+D su *nix)
                # - KeyboardInterrupt: se l'utente preme Ctrl+C
                message = input("Messaggio> ").strip()
            except EOFError:
                # EOF ricevuto: chiudiamo pulitamente il loop.
                print("\nEOF ricevuto. Chiusura.")
                break
            except KeyboardInterrupt:
                # Interruzione tramite tastiera: chiudiamo pulitamente.
                print("\nInterrotto da tastiera. Chiusura.")
                break

            # Se l'utente ha premuto solo Invio (stringa vuota), ignoriamo.
            if not message:
                continue

            # Comando 'exit' — terminazione volontaria del client.
            if message.lower() == "exit":
                print("Chiusura connessione...")
                break

            # Prepariamo i bytes da inviare: encode('utf-8') converte la str in bytes.
            # Nota: scegliere la codifica coerente lato server/lato client (qui UTF-8).
            wire = message.encode("utf-8")

            # Invia tutti i bytes; sendall si assicura di mandare l'intero buffer
            # (può bloccare temporaneamente; useremo timeout impostato prima).
            sock.sendall(wire)

            # Aspettiamo la risposta dal server. recv(bufsize) ritorna bytes oppure b''.
            # Per chiarezza gestiamo il socket.timeout separatamente.
            try:
                data = sock.recv(bufsize)
            except socket.timeout:
                # Se scade il timeout in recv: avvisiamo e continuiamo il loop.
                print("(timeout in ricezione)")
                continue

            # Se recv ha restituito b'' significa che il server ha chiuso la connessione.
            if not data:
                print("Connessione chiusa dal server.")
                break

            # Proviamo a decodificare la risposta come UTF-8. Se fallisce,
            # catturiamo UnicodeDecodeError e mostriamo i bytes grezzi.
            try:
                print("Risposta:", data.decode("utf-8"))
            except UnicodeDecodeError:
                # Se i bytes non sono UTF-8 validi, li stampiamo così come sono.
                print("Risposta (bytes):", data)

    except KeyboardInterrupt:
        # Se arriva KeyboardInterrupt mentre siamo fuori dal blocco input (es. durante connect),
        # gestiamo l'interruzione pulitamente (stampa e chiusura).
        print("\nInterrotto da tastiera. Chiusura.")
    except Exception as e:
        # Qualunque altra eccezione imprevista (es. network unreachable, connection refused, ecc.)
        # la mostriamo e terminiamo con codice di errore non-zero (sys.exit(1)).
        print(f"Errore: {e}")
        # sys.exit(1) forza l'uscita del processo con codice 1 (indica errore).
        sys.exit(1)
    finally:
        # Blocchetto finally: viene sempre eseguito, sia in caso di successo che in caso di eccezione.
        # Serve per garantire la chiusura della socket e il rilascio delle risorse.
        try:
            sock.close()
        except Exception:
            # Ignoriamo eventuali errori sulla close.
            pass
        print("Connessione chiusa.")



# Punto di ingresso dello script: parsing degli argomenti da linea di comando.
if __name__ == "__main__":
    # Il programma si aspetta esattamente 2 argomenti addizionali:
    # 1) server IP (o hostname)
    # 2) server port (numero intero)
    if len(sys.argv) != 3:
        # sys.argv[0] è il nome del programma eseguito
        print("Uso: python3 client.py <server_ip> <server_port>")
        sys.exit(1)


    # Recupero degli argomenti
    ip = sys.argv[1]
    try:
        # Converto la porta in intero; se non è un intero valido, segnalo errore.
        port = int(sys.argv[2])
    except ValueError:
        print("Errore: la porta deve essere un intero.")
        sys.exit(1)

    # Avvio la connessione e il loop di interazione.
    connect_to_server(ip, port)

