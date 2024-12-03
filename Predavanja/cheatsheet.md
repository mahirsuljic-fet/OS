# Generalno

| Skraćenica | Puni naziv
| :--------: | -----------
| OS         | Operating System
| CPU        | Central Processing Unit (procesor)
| RAM        | Random Access Memory (glavna memorija računara)
| MMU        | Memory Management Unit

| Termin         | Pojašnjenje
| -------------- | -----------
| Kernel         | glavni dio operativnog sistema
| Kernel mode    | mod rada procesora sa najvećim privilegijama (može izvršavati sve instrukcije)
| User mode      | mod rada procesora sa najmanjim privilegijama (ne može izvršavati privilegovane instrukcije)
| Real Mode      | 16-bit mod rada procesora
| Protected Mode | 32-bit mod rada procesora
| Chipset        | kontroler toka podataka između CPU i ostalih uređaja na matičnoj ploči
| Northbridge    | dio chipset-a koji prosljeđuje podatke brzim uređajima kao npr. u RAM, na PCIe bus (za GPU ili slično) ili southbridge-u
| Southbridge    | dio chipset-a koji prosljeđuje podatke sporim uređajima kao npr. USB, SATA, itd.
| sektor         | kontinualan dio memorije na disku



# Asembler

| Skraćenica | Puni naziv
| :--------: | -----------
| IP         | Instruction Pointer
| SP         | Stack Pointer (kraj, dno stack-a)
| BP         | Begin Pointer (početak, vrh stack frame-a)
| b          | bit
| B          | bajt

| Termin        | Pojašnjenje
| ------------- | -----------
| stack frame   | dio stack-a koji koristi funkcija koja se trenutno izvršava
| caller        | funkcija koja poziva drugu funkciju
| callee        | funkcija koju je pozvala neka druga funkcija
| leaf function | funkcija koja ne poziva druge funkcije
| prolog        | uvodni dio funkcije
| epilog        | završni dio funkcije
| flag          | bit sa posebnim značenjem
| byte          | 1 bajt (1B), 8 bita (8b)
| word          | 2 bajta (2B), 16 bita (16b)
| long          | 4 bajta (4B), 32 bita (32b)



# Adresiranje

| Termin                    | Pojašnjenje
| ------------------------- | -----------
| adresni prostor           | skup mogućih adresa
| virtuelni adresni prostor | adresni prostor koji koriste programi
| fizički adresni prostor   | adresni prostor koji koristi kontroler memorije, adrese fizičke memorije (RAM)
| logička adresa            | adresa iz logičkog adresnog prostora, adresa iz instrukcije
| linearna adresa           | logička adresa nakon segmentiranja
| fizička adresa            | adresa iz fizičkog adresnog prostora, adresa u fizičkog memoriji


## Segmentiranje

| Skraćenica | Puni naziv
| :--------: | :----------
| CPL        | Current Privilege Level
| GDT        | Global Descriptor Table
| LDT        | Local Descriptor Table
| DPL        | Descriptor Privilege Level
| RPL        | Requested Privilege Level

| Termin                    | Pojašnjenje
| ------------------------- | -----------
| segment                   | kontinualni blok memorije korišten pri segmentiranju
| (segment) deskriptor      | 64-bitna binarna struktura podataka koja opisuje segment
| (segment) selektor        | segmentni registar, zajedno sa keširanim deskriptorom
| CPL                       | nivo privilegija koji trenutno ima procesor<br>prva 3 bita registra `%cs`
| RPL                       | traženi nivo privilegija pri pristupu nekom segmentu<br>prva 3 bita selektora `%ss`, `%ds`, `%es`, `%fs` i `%gs` (svih osim `%cs`)
| DPL                       | potreban nivo privilegija da se pristupi segmentu koji opisuje dati deskriptor

### Pojašnjenja polja selektora
| Deskriptor polje | Veličina | Naziv                              | Pojašnjenje
| :--------------: | :------: | :--------------------------------: | -----------
| Index            | 13b      | Index                              | predstavlja indeks deskriptora u GDT sa kojim je dati selektor asociran, a time označava i segment sa kojim je asociran
| T(I)             | 1b       | Table (Indicator)                  | određuje koji se descriptor table koristi (0 - GDT, 1 - LDT)<br>mi ovaj bit označavamo sa T, ali u literaturi se može naći i oznaka TI
| RPL/CPL          | 2b       | Requested/Current Privilege Level  | određuje trenutni nivo privilegija koje ima procesor

### Pojašnjenja polja deskriptora
| Deskriptor polje | Veličina | Naziv                      | Pojašnjenje
| :--------------: | :------: | :------------------------: | -----------
| Base             | 32b      | Base                       | adresa koja označava početak segmenta
| Limit            | 20b      | Limit                      | adresa koja označava kraj segmenta
| G                | 1b       | Granularity                | određuje minimalnu i maksimalnu veličinu segmenta, kao i veličinu koraka kojim se veličina segmenta može regulisati <br> (0 - 0B do 1MB, korak 1B &nbsp;&thinsp;\|&nbsp;&thinsp; 1 - 4kB do 4GB, korak 4kB)
| D/B              | 1b       | Default/Big                | određuje da li je segment 16-bit (vrijednost 0) ili 32-bit (vrijednost 1)
| L                | 1b       | Long                       | određuje da li je segment 64-bitni, ukoliko je vrijednost 1, D/B mora biti 0 (ne koristimo 64-bit pa je uvijek 0)
| AVL              | 1b       | Available                  | koristi softver, ne koristi hardver
| P                | 1b       | Present                    | označava da li je segment pristutan/validan, pristupanjem segmentu sa P bitom 0 rezultuje iznimkom
| DPL              | 2b       | Descriptor Privilege Level | označava nivo privilegije potreban da se pristupi datom segmentu
| S                | 1b       | System                     | označava da li segment koristi sistem (vrijednost 0) ili neki drugi program (vrijednost 1)
| Type             | 4b       | Type                       | vrsta segmenta i kontrola pristupa (biti E\|DC\|RW\|A)

### Biti Type polja segment deskriptora
| Oznaka | Bit | Pojašnjenje
| :----: | :-: | -----------
| A      |  0  | Accessed, hardver postavi na 1 kada se pristupi segmentu, softver postavi na 0
| RW     |  1  | Read/Write, za code segment označava da li se može čitati iz njega, za data segment označava da li se može pisati u njega (nikad se ne može pisati u code segment, a uvijek se može čitati iz data segmenta)
| DC     |  2  | Direction/Conforming, za data segment označava smijer rasta segmenta (0 - gore, 1 - dole), za code segment: ako je 0 onda CPL mora biti jednak DPL, ako je 1 onda CPL može biti manji ili jednak DPL
| E      |  3  | Executable, ako je 0 onda se radi o data segmentu, ako je 1 onda se radi o code segmentu


## Paging

| Skraćenica | Puni naziv
| :--------: | :----------
| PD         | Page Directory
| PT         | Page Table
| PDE        | Page Directory Entry 
| PTE        | Page Table Entry
| PF         | Page Frame
| PDBR       | Page Directory Base Register

| Termin            | Pojašnjenje
| ----------------- | -----------
| stranica (page)   | kontinualan blok virtuelne memorije
| okvir (frame, PF) | kontinualan blok fizičke memorije
| PD                | niz PDE-ova
| PDE               | binarna struktura podataka koja opisuje PT-ove
| PT                | niz PTE-ova
| PTE               | stuktura podataka koja opisuje mapiranje u okvire
| PDBR              | drugi naziv na `%cr3`

### PDE
| Okvir |  OS  |  G   | (P)S |  D   |  A   | PCD  | PWT  |  U   | R/W  |  P   |
| :---: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| (20b) | (3b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) |

### Polja PDE
| Polje | Veličina | Naziv              | Pojašnjenje |
| :---: | :------: | ------------------ | ----------- |
| Okvir | 20b      | Okvir              | redni broj okvira u fizičkom memorijskom prostoru<br>ako je S bit 0 koristi se svih 20 bita<br>ako je S bit 1 koristi se godnjih 10 bita
| OS    | 3b       | Operating System   | ignorisani od strane hardvera, te ih OS može koristiti kako želi
| G     | 1b       | Global             | određuje da li je mapiranje globalno<br>ako PGE bit registra `%cr4` ima vrijednost 0 ovaj bit se ignoriše
| (P)S  | 1b       | (Page) Size        | diktira veličinu stranice<br>vrijednost 0 -> veličina stranice je 4kB<br>vrijednost 1 -> veličina stranice je 4MB<br>ako PSE (4.) bit registra `%cr4` ima vrijednost 0 onda se ovaj bit ignoriše<br>mi ovaj bit označavamo sa S, ali u literaturi se može naći i oznaka PS
| D     | 1b       | Dirty              | govori da li je softver pisao u ovo mapiranje<br>ako ovaj entry pokazuje na PT, onda se ovaj bit ignoriše
| A     | 1b       | Accessed           | govori da li je softver pristupio ovom mapiranju
| PCD   | 1b       | Page Cache Disable | [Intel](../Literatura/Intel_64_and_IA-32_Architectures_Manual.pdf) kaže _"indirectly determines the memory type used to access the 4-MByte page referenced by this entry (see Section 5.6)"_, šta god to značilo
| PWT   | 1b       | Page Write-Through | [Intel](../Literatura/Intel_64_and_IA-32_Architectures_Manual.pdf) kaže _"indirectly determines the memory type used to access the 4-MByte page referenced by this entry (see Section 5.6)"_, šta god to značilo
| U     | 1b       | User               | određuje da li procesor ima pristup ovom mapiranju ukoliko je u user modu
| R/W   | 1b       | Read/Write         | određuje da li se u ovom mapiranju mogu pisati/čitati podaci
| P     | 1b       | Present            | određuje da li se dato mapiranje koristi

### PTE
| Okvir |  OS  |  G   | PAT  |  D   |  A   |  C   |  W   |  U   | R/W  |  P   |
| :---: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| (20b) | (3b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) | (1b) |

### Polja PTE
| Polje | Veličina | Naziv                | Pojašnjenje |
| :---: | :------: | -------------------- | ----------- |
| Okvir | 20b      | Okvir                | redni broj okvira u fizičkom memorijskom prostoru<br>ako je S bit 0 koristi se svih 20 bita<br>ako je S bit 1 koristi se godnjih 10 bita
| OS    | 3b       | Operating System     | ignorisani od strane hardvera, te ih OS može koristiti kako želi
| G     | 1b       | Global             | određuje da li je mapiranje globalno<br>ako PGE bit registra `%cr4` ima vrijednost 0 ovaj bit se ignoriše
| PAT   | 1b       | Page Attribute Table | [Intel](../Literatura/Intel_64_and_IA-32_Architectures_Manual.pdf) kaže _"If the PAT is supported, indirectly determines the memory type used to access the 4-KByte page referenced by this entry (see Section 5.9.2); otherwise, reserved (must be 0)"_, šta god to značilo
| D     | 1b       | Dirty                | govori da li je softver pisao u ovo mapiranje
| A     | 1b       | Accessed             | govori da li je softver pristupio ovom mapiranju
| PCD   | 1b       | Page Cache Disable   | [Intel](../Literatura/Intel_64_and_IA-32_Architectures_Manual.pdf) kaže _"indirectly determines the memory type used to access the 4-MByte page referenced by this entry (see Section 5.6)"_, šta god to značilo
| PWT   | 1b       | Page Write-Through   | [Intel](../Literatura/Intel_64_and_IA-32_Architectures_Manual.pdf) kaže _"indirectly determines the memory type used to access the 4-MByte page referenced by this entry (see Section 5.6)"_, šta god to značilo
| U     | 1b       | User                 | određuje da li procesor ima pristup ovom mapiranju ukoliko je u user modu
| R/W   | 1b       | Read/Write           | određuje da li se u ovom mapiranju mogu pisati/čitati podaci
| P     | 1b       | Present              | određuje da li se dato mapiranje koristi


# Prekidi

| Skraćenica | Puni naziv
| :--------: | :---------
| ISR        | Interrupt Service Routine
| IDT        | Interrupt Descriptor Table

| Termin               | Pojašenjenje
| -------------------- | ------------
| ISR                  | funkcija koja radi interrupt handle
| IDT                  | tabela interrupt deskriptora
| Interrupt Descriptor | binarna struktura podataka koja opisuje kako će se tretirati neki prekid


# Procesi

| Skraćenica | Puni naziv
| :--------: | :---------
| TSS        | Task State Segment
| PCB        | Process Control Block
| PID        | Process IDentifier
| PPID       | Parent Process IDentifier

| Termin               | Pojašenjenje
| -------------------- | ------------
| TSS                  | 64-bitna binarna struktura podataka u kojoj se sprema stanje programa (procesora, tj. registara)
| PCB                  | struktura podataka koja opisuje proces
| PID                  | broj, jedinstveni identifikator svakog procesa
| Fork                 | funkcija koja pravi novi proces od već postojećeg procesa
| Shell                | proces koji omogućava kreiranje novih procesa
| Parent process       | proces od kojeg je nastao drugi proces (child process)
| Child process        | proces koji je nastao od drugog procesa (parent process)
| Orphan process       | proces kojem se parent process prestao izvršavati

| Stanja procesa | Opis
| :------------: | ----
| UNUSED         | ne koristi se, slobodno mjesto za neki proces
| EMBRYO         | procesa se pravi, ako fork ne uspije vraća u UNUSED, ako fork uspije prelazi u RUNNABLE
| RUNNABLE       | proces spreman na izvršavanje
| RUNNING        | proces se izvršava
| ZOMBIE         | proces prestaje sa izvršavanjem, sistemskim pozivom `wait` prelazi u UNUSED
| SLEEPING       | izvršio se "spori" sistemski poziv i proces čeka (npr. čeka podatke sa mreže)
