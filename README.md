# ISA projekt - NetFlow Exporter

**Autor:** Michal Blažek, xblaze34
**Datum:** 2. 11. 2022

## Popis
**flow** je NetFlow exportér, který analyzuje soubory obsahující zachycenou síťovou komunikaci ve formátu pcap. Vytváří záznamy NetFlow, které následně odesílá na kolektor.

## Odevzdané soubory

- Makefile
- main.c
- flows.c
- flows.h
- argparse.c
- argparse.h
- utilities.c
- utilities.h
- README
- manual.pdf
- flow.1

## Překlad

`$ make` - Překlad projektu  
`$ make clean` - Vymazání přeloženého projektu

## Spuštění

`./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]`

Pořadí argumentů je libovolné, všechny argumenty jsou nepovinné.

- **-f \<file\>** - Jméno analyzovaného souboru (nebo STDIN, pokud není zadán soubor).
- **-c \<netflow_collector\>[:\<port\>]** - IP adresa nebo hostname NetFlow kolektoru, případně UDP port (implicitně 127.0.0.1:2055).
- **-a \<active timer\>** - Interval v sekundách, po jehož vypršení se exportují aktivní záznamy (implicitně 60).
- **-i \<seconds\>** - Interval v sekundách, po jehož vypršení se exportují neaktivní záznamy (implicitně 10).
- **-m \<count\>** - Maximální počet právě otevřených flow. Při dosažení této hodnoty dojde k exportu nejstaršího záznamu. (implicitně 1024)

## Příklady použití

`./flow -f ./pcaps/file.pcap`  
`./flow -c localhost:5555 -a 30 -i 15 -m 64`
