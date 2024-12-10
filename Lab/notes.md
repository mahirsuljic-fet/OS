# Varijable

### Linker pointeri
| Naziv               | Opis
| ------------------- | ----
| `etext`             | kraj `.text` sekcije i početak `.rodata` sekcije kernela
| `__STAB_BEGIN__`    | početak `.stab` sekcije i kraj `.rodata` sekcije kernela
| `__STAB_END__`      | kraj `.stab` sekcije i početak `.stabstr` sekcije kernela
| `__STABSTR_BEGIN__` | početak `.stabstr` sekcije i kraj `.stab` sekcije kernela
| `__STABSTR_END__`   | kraj `.stabstr` sekcije kernela
| `edata`             | kraj `.data` sekcije i početak `.bss` sekcije kernela
| `end`               | kraj `.bss` sekcije kernela i samim tim i kraj kernela uopćeno

### Memorija
| Naziv            | Opis
| ---------------- | ----
| `basemem`        | količina base memorije (low memory dio RAM-a) (`0x000a0000`)
| `ext16mem`       | ukupna količina extended memorije (iznad 1MB)
| `totalmem`       | ukupna količina fizičke memorije
| `npages`         | ukupan broj okvira/stranica (do `totalmem`)
| `npages_basemem` | broj okvira/stranica u base memoriji (do `basemem`)
| `pages`          | niz `struct PageInfo` od `npages` elemenata, koristi se za praćenje svih okvira (čuva njihove metapodatke)

# Opisi funkcija

## `pmap.c`


### `mem_init`

#### Šta
Funkcija inicijalizira memoriju.
Alocira fizičku memoriju (`boot_alloc`), napravi page alokator (`pages`), napravi page directory za kernel (`kern_pgdir`) i postavi odgovarajuća mapiranja.

#### Kako
Detektuje koliko računar ima memorije pozivom funkcije `i386_detect_memory`.

Kreira inicijalni page directory koji će koristiti kernel.
To radi tako što alocira jednu stranicu memorije (koristeći `boot_alloc`, jer trenutno nema drugog načina) i "zapamti" je kao `kern_pgdir`.
Cijeli kernel page directory ispuni nulama.
Ovo se se radi da bi se `P` bit svakog PDE postavio na 0, čime se efektivno kaže da je ovaj page directory prazan.

Dodaje jedan PDE, i to za sam `kern_pgdir`.
Jedna stranica od adrese `UVPT` se mapira u okvir `kern_pgdir` sa user (`U` bit) permisijama.

Alocira se dovoljno mjesta za sve metapodatke o svim okvirima (niz od `npages` puta veličina od `struct PageInfo`).
Taj niz će se zvati `pages` i cijeli niz se popunjava nulama.
Popunjavanjem nulama se osigurava da svaki okvir nema referenci (`pp_ref` je 0) i da nema poveznicu (pointer) na neki drugi okvir (`pp_link` je NULL, odnosno 0).

Inicijaliziraju se metapodaci o okvirima (niz `pages`) pozivom funkcije `page_init`.

#### Zašto
Koristi se pri pokretanju sistema, odnosno njegovoj inicijalizaciji.
Poziva se unutar funkcije `i386_init` u fajlu `init.c`.


### `i386_detect_memory`

#### Šta
Detektuje koliko računar ima memorije.
Dodjeljuje vrijednost globalnih varijablama `npages` i `npages_basemem`.

#### Kako
Efektivno "pita" memoriju (RAM) koliko je ima.
To radi pozivanjem funkcije `nvram_read` (definisana u `pmap.c`) 
koja taj posao delegira funkciji `mc146818_read` (definisana u `kclock.c`) 
koja dalje delegira posao asembleru.

Sračuna ukupnu količinu memorije na osnovu base i extended memorije,
zatim sračuna ukupan broj stranica (`npages`) i broj stranica u base memoriji (`npages_basemem`).

#### Zašto
Koristi se kako bi se memorija mogla pravilno alocirati.
Budući da govori koliko ima ukupno memorije, na osnovu toga je moguće osigurati da nikad ne pristupimo nevalidnoj fizičkoj adresi 
(npr. pokušamo čitati sa adrese koja je veća nego što imamo RAM-a).

Poziva se unutar funkcije `mem_init` u fajlu `pmap.c`.


### `boot_alloc`

#### Šta
Funkcija alocira memoriju potrebnu sistemu kada se tek pokrene (odma nakon boot-anja).
Ne bi se trebala koristiti nakon što se inicijalizira i počne koristiti page allocator.

#### Kako
Pointer `nextfree` pokazuje na sljedeći bajt slobodne memorije.

Memorija se alocira `n` bajti memorije tako što:
- stara vrijednost `nextfree` (dakle prvi slobodni bajt memorije prije trenutne alokacije) "zapamti"
- `nextfree` se "pomjeri" za onoliko koliko memorije želimo alocirati (`n`) \
  (ali obavezno `nextfree` mora biti poravnat na veličinu stranice (`PGSIZE` što je 4096B))
- vrati se stara vrijednost `nextfree`

Funkcija vraća pointer, dakle neku adresu.
Nakon te adrese znamo sigurno da narednih `n` bajti (onoliko koliko smo tražili) niko drugi ne koristi.
U ovo možemo biti sigurno zato jer **trenutno** ništa drugo ne može alocirati memoriju, niti dealocirati.

#### Zašto
Koristi se za alokaciju page directory-a kernela (`kern_pgdir`) i za alokaciju ostatka fizičke memorije (inicijalizacija page alokatora, `pages`).


### `page_init`

#### Šta
Funkcija označava sve okvire koji se mogu proizvoljno koristiti kao slobodne.
Inicijalizira `pages` i listu slobodnih stranica (`page_free_list`).
Efektivno radi push front na `page_free_list` pri čemu popunjaje `pages` sa adekvatnim metapodacima.

#### Kako
**Napomena**\
Svaki element iz niza `pages` je tipa `struct PageInfo` i opisuje neki okvir. \
`pages[0]` opisuje nulti okvir, `pages[1]` opisuje prvi okvir, itd. \
`pages` je virtuelna adresa, ali opisuje okvir, koji je dio fizičke memorije.
Na osnovu `pages` znamo sve o okvirima, ako nas zanima peti okvir, `pages[5]` nam govori da li je on slobodan i koliko ima referenci na njega.
Tako da, kada kažem okvir, zapravo mislim na element iz niza `pages`, tipa `struct PageInfo`, koji opisuje okvir. \
Slobodan okvir ima `pp_ref` postavljen na `0`, a `pp_link` na sljedeći slobodan okvir. \
Zauzeti okvir okvir ima `pp_ref` različit od `0`, a `pp_link` postavljen na `NULL`.

Prvo se označava prvi okvir da nije slobodan, zbog IDT i ostalih struktura koje je BIOS tu postavio.
Ovo sprječava procese da mijenjaju pomenute strukture, jer se taj okvir nikada neće alocirati.

Dalje, označavaju se svi okviri iz base memorije (osim prvog) kao slobodni.

Od kraja base memorije do adrese 1MB se nalazi tzv. IO hole (Input/Output rupa).
To je dio fizičkog adresnog prostora koji nije mapiran u RAM (memoriju), nego u VGA, druge uređaje i BIOS.
Te stranice ne želimo da se ikada alociraju, pa ih označimo kao zauzete.

Dio fizičkog adresnog prostora u kojem se nalazi kernel, `kern_pgdir` i `pages` također ne želimo da se koriste, pa ćemo ih označiti kao zauzete.

Na kraju, sve okvire od kraja `pages` pa do kraja fizičke memorije 
(ne adresnog prostora, nego onoliko koliko memorije ima, kako nam je rekla funkcija `i386_detect_memory`) označimo kao slobodne.

#### Zašto
Ovim se označava koje okvire smijemo koristiti proizvoljno (npr. alociramo nekom procesu i znamo da smije raditi šta hoće tu, neće ništa pokvariti).
Ovim se također sprječava da dva procesa slučajno koriste isti okvir 
(ne bi bilo baš dobro da napišemo u svom programu `int a = 5;`, zatim isprintamo i vidimo da je neko promijenio tu vrijednost na 3453453).
Praktično, način na koji ćemo dodjeljivati memoriju je da uzmemo slobodan okvir iz `page_free_list` i dadnemo onome ko je tražio.
Funkcija se poziva iz `mem_init`.


---
#### TEMPLATE
```
### ``

#### Šta

#### Kako

#### Zašto

```
