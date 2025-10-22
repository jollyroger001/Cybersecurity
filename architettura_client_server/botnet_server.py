#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server TCP multithread semplice (echo in maiuscolo).
Questo file contiene commenti dettagliati **inline** che spiegano ogni pezzo del
codice e i metodi / attributi principali utilizzati.
"""

import socketserver
import threading

# ----------------------------
# Handler per ogni connessione
# ----------------------------
class BotRequestHandler(socketserver.BaseRequestHandler):
    """
    Classe che gestisce una singola connessione in ingresso.
    - Eredita da socketserver.BaseRequestHandler.
    - La libreria socketserver crea un'istanza di questa classe per ogni
      connessione e chiama il metodo .handle() su quell'istanza.
    """

    def handle(self):
        """
        Metodo principale chiamato dalla libreria socketserver quando
        viene stabilita una connessione TCP verso il server.
        Qui gestiamo il ciclo di ricezione/invio sulla socket connessa.
        """

        # self.client_address: tupla (host, port) dell'endpoint remoto.
        # self.client_address[0] è l'indirizzo IP del client.
        client_ip = self.client_address[0]

        # Recupera il nome del thread corrente (utile nei log).
        # threading.current_thread().name ritorna una stringa come "Thread-1".
        thread_name = threading.current_thread().name

        # Primo log: connessione accettata.
        print(f"[{thread_name}] Connessione ricevuta da: {client_ip}")

        try:
            # Ciclo di ricezione: riceve dati fino a quando il client chiude
            # la connessione o non viene ricevuto nulla.
            while True:
                # self.request è l'oggetto socket collegato al client.
                # recv(1024) legge fino a 1024 byte dal socket.
                # Se il peer chiude la connessione, recv restituisce b'' (bytes vuoto).
                data_bytes = self.request.recv(1024)

                # Se non ci sono più byte (client ha chiuso), interrompi il loop.
                if not data_bytes:
                    break

                # Decodifica i bytes in stringa usando UTF-8.
                # .decode('utf-8') converte i bytes in str.
                # .strip() rimuove newline / spazi estremi per una stampa più pulita.
                received_message = data_bytes.decode('utf-8').strip()

                # Log del messaggio ricevuto (mostra quale bot/client ha inviato).
                print(f"[{thread_name}] Bot {client_ip} ha inviato: '{received_message}'")

                # Qui applichiamo la "logica" del servizio: trasformare in maiuscolo.
                # response_message sarà la stringa di risposta che invieremo al client.
                response_message = received_message.upper()

                # Per inviare, convertiamo la stringa in bytes (encode UTF-8)
                # e usiamo self.request.sendall(...) per inviare tutti i bytes.
                # sendall() prova ad inviare tutti i bytes finché non sono stati mandati;
                # se si verifica un errore genera un'eccezione.
                self.request.sendall(response_message.encode('utf-8'))

        except ConnectionResetError:
            # Questa eccezione viene lanciata se il peer chiude la connessione
            # in modo brusco (reset della connessione). È normale in ambienti di rete.
            print(f"[{thread_name}] La connessione con {client_ip} è stata interrotta bruscamente.")
        except Exception as e:
            # Cattura generica per altri errori imprevisti durante la gestione
            # della connessione (es. errori di decodifica, socket, ecc.).
            print(f"[{thread_name}] Errore durante la gestione della connessione con {client_ip}: {e}")
        finally:
            # Il blocco finally viene sempre eseguito: qui possiamo fare log di chiusura.
            # Notare: non chiudiamo esplicitamente self.request qui perché
            # socketserver si occupa normalmente di chiudere la socket alla fine
            # della gestione; tuttavia chiudere esplicitamente sarebbe accettabile.
            print(f"[{thread_name}] Connessione chiusa con: {client_ip}")


# ----------------------------
# Funzione main: avvia server
# ----------------------------
def main():
    # HOST "0.0.0.0" significa "bind su tutte le interfacce disponibili".
    # PORT 8000 è la porta TCP sulla quale il server ascolterà.
    HOST, PORT = "0.0.0.0", 8000

    # socketserver.ThreadingTCPServer.allow_reuse_address = True
    # - allow_reuse_address è un attributo di classe usato dal server TCP.
    # - Se True, permette di riusare l'indirizzo/porta immediatamente dopo che
    #   il server è terminato (utile durante sviluppo per evitare "address already in use").
    # - Va impostato **prima** di creare l'istanza del server.
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    try:
        # Creiamo il server usando socketserver.ThreadingTCPServer:
        # - ThreadingTCPServer crea un nuovo thread per ogni connessione accettata.
        # - Il costruttore prende la tupla (HOST, PORT) e la classe handler.
        # - Usando il context manager "with ... as server:" ci assicuriamo che
        #   server.server_close() venga chiamato al termine del blocco.
        with socketserver.ThreadingTCPServer((HOST, PORT), BotRequestHandler) as server:
            # Stampa informativa: server avviato
            print(f"Server multithread in ascolto su {HOST}:{PORT}")
            print("Premi CTRL+C per arrestare il server.")

            # server.serve_forever() entra nel loop principale del server:
            # - accetta connessioni, crea istanze di BotRequestHandler e chiama .handle()
            # - poll_interval opzionale può essere passato (qui usato default interno)
            # - serve_forever() blocca il thread corrente finché non viene chiamato shutdown()
            server.serve_forever()
    except KeyboardInterrupt:
        # Questa eccezione viene sollevata quando l'utente preme CTRL+C.
        # È usata qui per fare un'uscita "pulita".
        print("\nArresto del server richiesto dall'utente...")
    finally:
        # Eseguito sempre, sia in caso normale che dopo KeyboardInterrupt.
        # Qui possiamo mettere eventuali azioni di cleanup (log, risorse, ecc.).
        print("Server arrestato.")


# Punto di ingresso quando esegui lo script direttamente:
if __name__ == "__main__":
    main()
