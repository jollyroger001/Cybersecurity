#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan.py
Esempio didattico di probe ICMP + SYN scan con Scapy.
Uso: sudo python3 syn_scan.py <IP> <PORT>
"""

from scapy.all import IP, ICMP, TCP, sr1, conf
import sys
import random

# Disabilitiamo gli output troppo verbosi di Scapy (opzionale)
conf.verb = 0

def icmp_probe(ip: str, timeout: int = 3):
    """
    Invia un pacchetto ICMP (ping) e attende una singola risposta.
    - IP(dst=ip)/ICMP() : costruisce un pacchetto IP con inside un payload ICMP Echo Request.
    - sr1(pkt, timeout=..) : invia il pacchetto e attende la prima risposta; ritorna la risposta
      oppure None se non arriva nulla entro il timeout.
    Parametri:
      ip: destinazione (stringa)
      timeout: secondi da attendere per la risposta
    Ritorna:
      True se l'host risponde (qualsiasi risposta ICMP che arriva), False altrimenti.
    NOTE SCAPY:
      sr1() invia e riceve *solo* il primo pacchetto di risposta (utile per probe singoli).
      Per inviare più pacchetti e ricevere più risposte si usa sr(), che ritorna (answered, unanswered).
    """
    # Costruzione del pacchetto: header IP + ICMP Echo Request
    pkt = IP(dst=ip) / ICMP()
    # sr1 restituisce il pacchetto di risposta o None
    resp = sr1(pkt, timeout=timeout)
    return resp is not None

def syn_scan(ip: str, port: int, timeout: int = 3):
    """
    Invia un pacchetto TCP con flag SYN (scansione SYN / "half-open") e ritorna la risposta se presente.
    - TCP(dport=port, sport=source_port, flags='S') : costruisce header TCP con SYN.
    - sr1(packet, timeout=..) : invia e aspetta una singola risposta (SYN/ACK, RST, o niente).
    Controlli da effettuare sulla risposta:
      - se None: nessuna risposta -> possibile filtro/host down/porta filtrata
      - se c'è uno strato TCP nella risposta:
          . flags == 0x12 (SYN+ACK) -> porta aperta (risposta tipica a SYN)
          . flags == 0x14 (RST+ACK) -> porta chiusa (RST)
          . altri flag -> interpretare con cautela
    Parametri:
      ip: indirizzo destinazione
      port: porta (int)
      timeout: timeout in secondi
    Ritorna:
      la risposta ricevuta (oggetto Scapy Packet) oppure None
    """
    # Scegliamo una porta sorgente casuale alta per evitare collisioni (non obbligatorio)
    sport = random.randrange(1025, 65535)
    # Costruzione del pacchetto SYN
    syn_pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S')
    # Invia e aspetta la prima risposta (sr1)
    resp = sr1(syn_pkt, timeout=timeout)
    return resp

def interpret_tcp_flags(tcp_layer):
    """
    Interpreta i flag di un livello TCP (oggetto Scapy) e ritorna una stringa descrittiva.
    I flag vengono letti come un valore numerico (es: 0x12) o come stringa di flag (es: 'SA').
    """
    # Scapy può rappresentare flags come stringa ('SA' ecc.) o come valore intero.
    flags = tcp_layer.flags
    # Confronti numerici:
    # 0x02 -> SYN
    # 0x10 -> ACK
    # 0x12 -> SYN+ACK
    # 0x14 -> RST+ACK
    try:
        # Proviamo a ottenere il valore intero (se possibile)
        flags_int = int(flags)
    except Exception:
        # Se non è convertibile, usiamo la rappresentazione testuale
        flags_int = None

    desc = []
    if flags_int is not None:
        if flags_int & 0x02:
            desc.append("SYN")
        if flags_int & 0x10:
            desc.append("ACK")
        if flags_int & 0x04:
            desc.append("RST")
        if flags_int & 0x01:
            desc.append("FIN")
        if flags_int & 0x08:
            desc.append("PSH")
        if flags_int & 0x20:
            desc.append("URG")
        if flags_int & 0x40:
            desc.append("ECE")
        if flags_int & 0x80:
            desc.append("CWR")
        desc_str = "+".join(desc) if desc else f"FLAG_RAW=0x{flags_int:02x}"
    else:
        # fallback: mostra la stringa di Scapy
        desc_str = str(flags)
    return desc_str

def main():
    # parsing argomenti: minimo 2 argomenti (ip e porta)
    if len(sys.argv) < 3:
        print("Uso: sudo python3 syn_scan.py <IP> <PORT>")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Errore: <PORT> deve essere un intero.")
        sys.exit(1)

    print(f"[+] ICMP probe verso {ip} ...")
    if not icmp_probe(ip, timeout=2):
        print("[-] ICMP Probe fallito: l'host potrebbe essere non raggiungibile o ICMP bloccato.")
        # Nota: molti host bloccano ICMP; in ambiente di laboratorio potresti voler procedere comunque.
        sys.exit(1)

    print(f"[+] Host {ip} raggiungibile. Avvio SYN scan sulla porta {port} ...")
    resp = syn_scan(ip, port, timeout=3)

    if resp is None:
        # Nessuna risposta ricevuta: porta filtrata o host non risponde al livello TCP
        print("[-] Nessuna risposta TCP ricevuta (timeout). La porta potrebbe essere filtrata o bloccata.")
        sys.exit(0)

    # Verifichiamo che nella risposta ci sia effettivamente uno strato TCP
    if resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)
        flags_desc = interpret_tcp_flags(tcp_layer)
        print(f"[+] Pacchetto TCP di risposta ricevuto: flags = {tcp_layer.flags} -> {flags_desc}")

        # Controllo puntuale del valore numerico: SYN+ACK tipicamente 0x12 (18 decimale)
        # RST+ACK tipicamente 0x14 (20 decimale)
        try:
            flags_value = int(tcp_layer.flags)
        except Exception:
            # Se la conversione fallisce, saltiamo il controllo numerico
            flags_value = None

        if flags_value == 0x12:
            print(f"[OK] Porta {port} aperta (risposta SYN+ACK).")
            # In una SYN-scan reale, qui si dovrebbe inviare RST per non completare la connessione
            # es: send(IP(dst=ip)/TCP(sport=tcp_layer.dport, dport=tcp_layer.sport, flags='R'))
        elif flags_value == 0x14:
            print(f"[-] Porta {port} chiusa (ricevuto RST).")
        else:
            print(f"[?] Risposta TCP non standard: valore flags 0x{flags_value:02x} (se disponibile).")
    else:
        # Se non c'è tcp layer, possiamo avere un ICMP di errore (es. host unreachable)
        print("[-] La risposta non contiene layer TCP. Potrebbe essere arrivato un messaggio ICMP di errore.")
        # Se vogliamo possiamo mostrare il pacchetto completo per debugging:
        resp.show()

if __name__ == "__main__":
    main()