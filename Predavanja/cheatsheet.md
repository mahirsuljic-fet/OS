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
| (segment) deskriptor      | 64-bitna struktura koja opisuje segment
| (segment) selektor        | segmentni registar, zajedno sa keširanim deskriptorom

### Pojašnjenja polja selektora

| Deskriptor polje | Veličina | Naziv                      | Pojašnjenje
| :--------------: | :------: | :------------------------: | -----------
| Index            | 13b      | Index                      | predstavlja indeks deskriptora u GDT sa kojim je dati selektor asociran, a time označava i segment sa kojim je asociran
| T(I)             | 1b       | Table (Indicator)          | određuje koji se descriptor table koristi (0 - GDT, 1 - LDT)

### Pojašnjenja polja deskriptora
| Deskriptor polje | Veličina | Naziv                      | Pojašnjenje
| :--------------: | :------: | :------------------------: | -----------
| Base             | 32b      | Base                       | adresa koja označava početak segmenta
| Limit            | 20b      | Limit                      | adresa koja označava kraj segmenta
| G (1b)           | 1b       | Granularity                | određuje minimalnu i maksimalnu veličinu segmenta, kao i veličinu koraka kojim se veličina segmenta može regulisati <br> (0 - 0B do 1MB, korak 1B &nbsp;&thinsp;\|&nbsp;&thinsp; 1 - 4kB do 4GB, korak 4kB)
| D/B              | 1b       | Default/Big                | određuje da li je segment 16-bit (vrijednost 0) ili 32-bit (vrijednost 1)
| L                | 1b       | Long                       | određuje da li je segment 64-bitni, ukoliko je vrijednost 1, D/B mora biti 0 (ne koristimo 64-bit pa je uvijek 0)
| AVL              | 1b       | Available                  | koristi softver, ne koristi hardver
| P                | 1b       | Present                    | označava da li je segment pristutan/validan, pristupanjem segmentu sa P bitom 0 rezultuje iznimkom
| DPL              | 2b       | Descriptor Privilege Level | označava nivo privilegije potreban da se pristupi datom segmentu
| S                | 1b       | System                     | označava da li segment koristi sistem (vrijednost 0) ili neki drugi program (vrijednost 1)
| Type             | 4b       | Type                       | vrsta segmenta i kontrola pristupa (biti E\|DC\|RW\|A)

### Biti Type polja segment deskriptora
| Oznaka | Indeks      | Pojašnjenje
| :----: | :---------: | -----------
| A      | 0           | Accessed, hardver postavi na 1 kada se pristupi segmentu, softver postavi na 0
| RW     | 1           | Read/Write, za code segment označava da li se može čitati iz njega, za data segment označava da li se može pisati u njega (nikad se ne može pisati u code segment, a uvijek se može čitati iz data segmenta)
| DC     | 2           | Direction/Conforming, za data segment označava smijer rasta segmenta (0 - gore, 1 - dole), za code segment: ako je 0 onda CPL mora biti jednak DPL, ako je 1 onda CPL može biti manji ili jednak DPL
| E      | 3           | Executable, ako je 0 onda se radi o data segmentu, ako je 1 onda se radi o code segmentu
