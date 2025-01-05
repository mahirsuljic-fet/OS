# The ROM BIOS

## Exercise 2
Prilikom pokretanja računara BIOS postavlja radno okruženje.
BIOS inicijalizira stack u low memory dijelu adresnog prostora.
Dalje vrši inicijalizaciju IDT i GDT, te prelazi u protected mod.
Dalje vrši inicijalizaciju ostalih uređaja kao đto su VGA display i komunikaciju sa njima (printanje na ekran i slično).
Kasnije počne tražiti boot sektor. Kada ga nađe učita boot loader sa diska u memoriju i preda mu kontrolu.
Kada BIOS preda kontrolu boot loaderu `%eip` ima vrijednost `0x7c00`, što je adresa prve instrukcije boot loadera.

# The Boot Loader

## Exercise 3
Razlika između orginalnog boot loader koda ([`boot.S`](../boot/boot.S)) i disasembliranog boot loader koda (`boot.asm`) su sljedeće:
- `boot.asm` pored asembler koda koji se nalazi u `boot.S`, također sadrži i kod iz [`main.c`](../boot/main.c) koji je kompajliran u asembler, dakle nema nerasjašnjenih simbola
- `boot.asm` pored instrukcija također ima označene adrese instukcija i drugih labela, i hex zapis instrukcija \
  (_npr_. `cli` je `0xfa` i nalazi se na adresi `0x7c00`)
- U `boot.asm` labele i varijable (definisane predprocesorom) su zamijenjene konkretnim konstantama \
  (_npr_. `orl $CR0_PE_ON, %eax` je zamijenjeno sa `or $0x1, %ax`)
- U `boot.asm` korišteni su 32-bitni registri i "osnovne" verzije instrukcija (ali jasno, dok je procesor u real modu, koristi se samo donjih 16 bita registara) \
  (_npr_. umjesto `xorw %ax, %ax` (u `boot.S`) koristi se `xor %eax, %eax`)
- U `boot.asm` predprocesorski makroi su prevedeni u instrukcije (i eventualno direktive)

Zadnja instrukcija koja se izvršava iz `boot.S` je `call bootmain` (odnosno `0x7d19`).
Funkcija `bootmain` je definisana u `main.c`, pa se od te instrukcije izvršava c kod napisan u `main.c`.

Unutar `bootmain` poziva se funkcija `readseg` sa argumentima `(uint32_t) ELFHDR`, `SECTSIZE*8` i `0`.
Instrukcija koja odgovara pozivu `bootmain` je `call 0x7cda`.
Prvi argument funkcije `readseg` predstavlja fizičku adresu (`pa`) gdje će boot loader da učita podatke.
Drugi argument predstavlja broj bajta koji se čitaju.
Treći argument predstavlja adresu odakle se podaci čitaju.

Korištenjem funkcije `readsect` učitaju se sektori koji sadrže kernel u memoriju.
Instrukcija koja odgovara pozivu `readsect` je `call 0x7c78`.
Prvi argument predstavlja adresu gdje će boot loader da učita podatke.
Drugi argument predstavlja adresu odakle će boot loader čitati podatke, pri čemu sada `offset` predstavlja broj sektora, a ne adresu.

Funkcija `readsect` poziva funkciju `waitdisk` koja ispituje da li je disk slobodan i ako nije, jednostavno čeka da disk postane slobodan.
Instrukcija koja odgovara pozivu `waitdisk` je `call 0x7c6a`.

Izrazi iz `readsect` i korespondirajuće asembler instrukcije:
izraz                                 | instrukcija                                                                                         |
------------------------------------- | --------------------------------------------------------------------------------------------------- |
`waitdisk()`                          | `call 0x7c6a`                                                                                       |
`outb(0x1F2, 1)`                      | `mov $0x1, %al`,  `mov $0x1f2, %edx`, `out %al, (%dx)`                                              |
`outb(0x1F3, offset)`                 | `mov %ecx, %eax`, `mov $0x1f3, %edx`, `out %al, (%dx)`                                              |
`outb(0x1F4, offset >> 8)`            | `mov %ecx, %eax`, `mov $0x1f4, %edx`, `shr $0x8, %eax`,  `out %al, (%dx)`                           |
`outb(0x1F5, offset >> 16)`           | `mov %ecx, %eax`, `mov $0x1f5, %edx`, `shr $0x10, %eax`, `out %al, (%dx)`                           |
`outb(0x1F6, (offset >> 24) \| 0xE0)` | `mov %ecx, %eax`, `mov $0x1f6, %edx`, `shr $0x18, %eax`, `or $0xffffffe0, %eax`, `out %al, (%dx)`   |
`outb(0x1F7, 0x20)`                   | `mov $0x20, %al`, `mov $0x1f7, %edx`, `out %al, (%dx)`                                              |
`waitdisk()`                          | `call 0x7c6a`                                                                                       |
`insl(0x1F0, dst, SECTSIZE/4)`        | `mov 0x8(%ebp), %edi`, `mov $0x80, %ecx`, `mov $0x1f0, %edx`, `cld`, `repnz insl (%dx), %es:(%edi)` |

Adrese od `0x1f0` do `0x1f7` su adrese koje se koriste za kontrolisanje primarnog ATA bus-a ([_source_: Primary/Secondary Bus](https://wiki.osdev.org/ATA_PIO_Mode)), te se koriste za komunikaciju sa diskom.\
Adrese ATA IO porta i korespondirajući registri ([_source_: Registers](https://wiki.osdev.org/ATA_PIO_Mode)):
- `0x1f0` - Data Register 	                    
- `0x1f1` - Error Register 	                    
- `0x1f1` - Features Register 	                
- `0x1f2` - Sector Count Register 	            
- `0x1f3` - Sector Number Register (LBAlo) 	    
- `0x1f4` - Cylinder Low Register / (LBAmid) 	
- `0x1f5` - Cylinder High Register / (LBAhi) 	
- `0x1f6` - Drive / Head Register 	            
- `0x1f7` - Status Register 	                
- `0x1f7` - Command Register 	                

Dakle, sa `outb(0x1F2, 1)` se označava da će se čitati samo jedan sektor.
Sa `outb(0x1F3, offset)`, `outb(0x1F4, offset >> 8)`, `outb(0x1F5, offset >> 16)` i `outb(0x1F6, (offset >> 24) | 0xE0)` se označava odakle će se čitati podaci.
Sa `outb(0x1F7, 0x20)` se određuje komanda koja će se koristiti, u ovom slučaju je to `0x20` koja označava čitanje.

Izrazom `insl(0x1F0, dst, SECTSIZE/4)` se čita `SECTSIZE/4` (128) bajti sa porta, adrese `0x1f0` (dakle, sa diska) i pohranjuje na adresu `dst`.

Petlja koja čita ostatak kernela sa diska je:
``` c
for (; ph < eph; ph++)
	readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
```
Početak te petlje u asembleru je na adresi `0x7d56`, instrukcija `cmp %esi, %ebx`.
Kraj petlje je na adresi `0x7d71`, na koju se dolazi skokom pomoću instrukcije `jae 0x7d71`.
Prva instrukcija posle petlje je `call *0x10018` koja odgovara izrazu `((void (*)(void)) (ELFHDR->e_entry))()`.
Ta instrukcija je skok na label `entry` iz [`entry.S`](../kern/entry.S) sto predstavlja entry point kernela.
Dakle, nakon pomenutog poziva kontrola se predaje kernelu.

### _At what point does the processor start executing 32-bit code? What exactly causes the switch from 16-bit to 32-bit mode?_
Instrukcijom `movl %eax, %cr0` se nulti bit registra `%cr0` postavlja na `1`.
Upravo to uzrokuje prelazak iz real moda (16-bit) u protected mode (32-bit).
Međutim, zbog direktive `.code16`, i dalje se program nalazi u dijelu koda gdje su 16-bitne instrukcije.
Zbog toga se koristi posebna instrukcija `ljmp $PROT_MODE_CSEG, $protcseg` koja je 16-bitna, 
ali se može izvršiti u protected modu i njome se vrši skok na dio koda koji sadrži 32-bitne instrukcije.
Ispred tog dijela koda se nalazi direktiva `.code32` koja označava da su sve instrukcije od te adrese 32-bitne.

### _What is the last instruction of the boot loader executed, and what is the first instruction of the kernel it just loaded?_
Zadnja instrukcija boot loadera je `call *0x10018`, a prva instrukcija kernela je `movw $0x1234, 0x472`.

### _Where is the first instruction of the kernel?_
Prva instrukcija kernela se nalazi u `entry.S` na adresi `0xf010000c`.

### _How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?_
Boot loader pročita prvi sektor u kojem se nalazi kernel (drugi sektor na disku).
Unutar tog sektora, prvih 52 bajta je ELF header kernela.
Unutar ELF headera se nalaze informacije o program headerima kernela.
Unutar svakog program headera se nalazi adresa gdje počinje korespondirajuća sekcija i njena veličina.
Dakle, boot loader iz ELF headera pročita veličinu svih sekcija kernela i učita sve sektore koji sadrže kernel.

## Exercise 5
Prva instrukcija koja ne uradi ono što treba je `lgdt gdtdesc` jer učitaje GDT sa pogrešnog mjesta i time u GDTR ne budu tačne vrijednosti.

Za `-Ttext 0x0000` gdje je GDT `00000064 <gdtdesc>:` dobijeni ispis za taj dio memorije je:
```
(gdb) x/2b 0x00000064
0x64:   0xf2    0xe6
```

A za korektne postavke `-Ttext 0x7C00` GDT je `00007c64 <gdtdesc>:` i dobijeni ispis za taj dio memorije je:
```
(gdb) x/2b 0x00007c64
0x7c64: 0x17    0x00
```

Također, instrukcija `ljmp $PROT_MODE_CSEG, $protcseg` ne preusmjeri tok programa na željeni način jer se u `%cs` učita pogrešna vrijednost.

Vrijednost `%cs` za `-Ttext 0x0000` nakon navedene instrukcije:
```
(gdb) info register cs
cs             0xf000              61440
```

Vrijednost `%cs` za `-Ttext 0x7C00` nakon navedene instrukcije:
```
(gdb) info register cs
cs             0x8                 8
```

## Exercise 6
Stanje memorije pri početku izvršavanja boot loadera:
```
0x100000:       0x00000000      0x00000000      0x00000000      0x00000000
0x100010:       0x00000000      0x00000000      0x00000000      0x00000000
```

Stanje memorije pri početku izvršavanja kernela:
```
0x100000:       0x1badb002      0x00000000      0xe4524ffe      0x7205c766
0x100010:       0x34000004      0x0000b812      0x220f0011      0xc0200fd8
```

U prvom slučaju ništa nije učitano u memoriju, dok u drugom slučaju se na adresi `0x100000` nalazi početak kernela.

# The Kernel

## Exercise 7
U fajlu [`entry.S`](../kern/entry.S) se uključuje straničenje.
Prije nego što se uključi, potrebno je podesiti page directory i odgovarajuće page table-e.
Registar `%cr3` treba da sadrži adresu od page directory-a koji se trenutno koristi.
Ispod je dio koda koji to radi:
```
	movl	$(RELOC(entry_pgdir)), %eax
	movl	%eax, %cr3
```
Iz koda se može zaključiti da je `entry_pgdir` simbol koji pokazuje na page directory koji će se koristiti.
Taj simbol je niz `pde_t` definisan u [`entrypgdir.c`](../kern/entrypgdir.c):
```
pde_t entry_pgdir[NPDENTRIES]
  = {
      // Map VA's [0, 4MB) to PA's [0, 4MB)
      [0]
      = ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P,
      // Map VA's [KERNBASE, KERNBASE+4MB) to PA's [0, 4MB)
      [KERNBASE >>
        PDXSHIFT]
      = ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P + PTE_W
    };
```
i definiše dva mapiranja:
- od `0x0` do `4MB` virtuelne memorije u `0x0` do `4MB` fizičke memorije
- od `KERNBASE` do `KERNBASE + 4MB` virtuelne memorije u `0x0` do `4MB` fizičke memorije

Dakle, nakon uključivanja straničenja prvim 4MB fizičke memorije se može pristupati sa niskih adresa (4MB od `0x0`) ili visokih adresa (4MB od `KERNBASE`).
Kernel je linkan na adresu `KERNBASE + 1MB`, što znači da će simbol `entry_pgdir` biti iznad te adrese, 
a budući da u `%cr3` mora biti fizička adresa page directory-a, potrebno je relocirati taj simbol pomoću makroa `RELOC`.

Straničenje se uključuju postavljanjem paging bita registra `%cr0` (`CR0_PG`) na 1.
Ispod je dio koda koji uljučuje straničenje:
```
	movl	%cr0, %eax
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0
```

Nakon ove instrukcije uključeno je straničenje.
Pomoću GDB se može dokazati je straničenje uključeno provjeravajući memoriju na niskim i visokim adresama prije i posle straničenja.

Memorija prije uključivanja straničenja:
```
(gdb) x/8x 0x00100000
0x100000:       0x1badb002      0x00000000      0xe4524ffe      0x7205c766
0x100010:       0x34000004      0x0000b812      0x220f0011      0xc0200fd8
(gdb) x/8x 0xf0100000
0xf0100000 <_start-268435468>:  Cannot access memory at address 0xf0100000
```

Memorija nakon uključivanja straničenja:
```
(gdb) x/8x 0x00100000
0x100000:       0x1badb002      0x00000000      0xe4524ffe      0x7205c766
0x100010:       0x34000004      0x0000b812      0x220f0011      0xc0200fd8
(gdb) x/8x 0xf0100000
0xf0100000 <_start-268435468>:  0x1badb002      0x00000000      0xe4524ffe      0x7205c766
0xf0100010 <entry+4>:           0x34000004      0x0000b812      0x220f0011      0xc0200fd8
```

Razlog zašto su ispisi nakon uključivanja straničenja isti je činjenica da je 4MB virtuelne memorije od `0xf0000000` (`KERNBASE`)
mapirano u 4MB fizičke memorije od `0x00000000`.

Ukoliko se na uključi straničenje, prva instrukcija koja neće raditi kako treba je `jmp *%eax`.
Ovo se može i testirati pomoću GDB ukoliko se izbriše/zakomentariše instrukcija `movl %cr0, %eax`:
```
=> 0x10002a:    jmp    *%eax
0x0010002a in ?? ()
(gdb) info register eax
eax            0xf010002c          -267386836
(gdb) si
=> 0xf010002c <relocated>:      Error while running hook_stop:
Cannot access memory at address 0xf010002c
```

Također, ukoliko ne bi bilo mapiranja `[0, 4MB)` virtuelne u `[0, 4MB)` fizičke memorije, 
jump instrukcija nakon uključivanja straničenja ne bi uspjela (pogledati ***Question 6*** iz [`answers_2`](./answers_2.md)).


## Formatted Printing to the Console

### 1. Explain the interface between `printf.c` and `console.c`. Specifically, what function does `console.c` export? How is this function used by `printf.c`?
[`console.c`](../kern/console.c) eksportuje funkciju `cputchar` koja se koristi za printanje karaktera na terminal.

### 2. Explain the following from `console.c`:
``` c
	if (crt_pos >= CRT_SIZE) {
		int i;
		memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
		for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
			crt_buf[i] = 0x0700 | ' ';
		crt_pos -= CRT_COLS;
	}
```

Ako cursor pređe kraj terminala, svi redovi se pomjere za jedan (prvi ispisani red se briše), 
zatim se zadnji red (gdje je cursor) ispunjaje praznim mjestima i cursor se pomijera na početak reda.

### 3. Trace the execution of the following code step-by-step:
``` c
int x = 1, y = 3, z = 4;
cprintf("x %d, y %x, z %d\n", x, y, z);
```
#### In the call to cprintf(), to what does fmt point? To what does ap point?
#### List (in order of execution) each call to cons_putc, va_arg, and vcprintf. For cons_putc, list its argument as well. For va_arg, list what ap points to before and after the call. For vcprintf list the values of its two arguments.

Argumenti se pushaju na stack redoslijedom `z`, `y`, `x` i na kraju adresa string literala `"x %d, y %x, z %d\n"`.
Zatim se vrši poziv funkcije `cprintf`.
Varijabla `fmt` pokazuje na string literal, a `ap` pokazuje na ostatak argumenata (preciznije, pokazuje na `x` koji prvi argument posle `fmt`).

Poziva se `vcprintf` sa argumentima `fmt` i `ap`, koji zatim poziva `vprintfmt` sa argumentima `putch` (pointer na funkciju), 
`&cnt` (pointer na brojač), `fmt` (pointer na string literal) i `ap` (pointer na `x`).

Dalje, poziva se `putch` sa argumentima `ch` (predstavlja trenutni karakter iz `fmt` koji treba isprintati) i `putdat` (pointer na `cnt`),
koji zatim poziva `cputchar` sa argumentom `ch`, koji poziva `cons_putc` u koji prosljeđuje argument `ch` (koji se sada "zove" `c`).

Zatim `cons_putc` poziva `serial_putc` sa argumentom `c` koji dati argument ispisuje na serijski port. \
Zatim `cons_putc` poziva `lpt_putc` sa argumentom `c` koji dati argument ispisuje na paralelni port. \
Zatim `cons_putc` poziva `cga_putc` sa argumentom `c` koji dati argument ispisuje na monitor tako što promijeni vrijednost u `crt_buf` i zatim pomjeri cursor (_).

Sada je `x` ispisano na monitor.

Prelazi na sljedeći karakter i ponavlja isti proces, te se na monitor ispisuje ` `.

Sada program dolazi do karaktera `%` koji označava format te se treba posebno tretirati.
Tok programa unutar `vprintfmt` jer preusmjeren na dio koji tretira formate i zatim analizira naredni karakter.
U ovom slučaju to je karakter `d`, te program ide na dio koji tretira cijele brojeve sa predznakom.
Poziva se funkcija `getint` sa argumentima `&va` (pointer na `va` koji je pointer na `x`) i `lflag` (`int` sa vrijednosti `0`, jer printamo `int`, a ne `long` ili `long long`).

Funkcija `getint` vraća vrijednost dobijenu izvršenjem makroa `va_arg` sa argumentima 
`*ap` (što je vrijednost od `x` i iznosi `1`) i `int` (tip od `x`, odnosno onoga na šta `ap` pokazuje).

Dalje, navodi se baza broja koji se printa (`base = 10`) i program ide na dio koda koji zapravo printa broj, 
te poziva funkciju `printnum` sa argumentima 
`putch`  (pointer na funkciju za printanje), 
`putdat` (brojač), 
`num`    (broj koji se printa), 
`base`   (baza broja koji se printa), 
`width`  (broj karaktera u koliko se broj printa, koristi se za padding) i 
`padc`   (karakter koji se koristi za padding).
Funkcija `printnum` printa broj pomoću funkcije na koju pokazuje `putch`, a to je funkcija `putch` definisana u `printf.c`.
U ovom slučaju `putch` se poziva sa argumentima `49` (parametar `ch`, karakter `'1'`, prva i jedina cifra od `x`) i pointer na `0` (parametar `cnt`, pointer na `putdata`).
Dalje `putch` poziva `cputchar` sa argumentom `49` koja poziva `cons_putc` sa argumentom `49`.
Zatim se pozivaju funkcije `serial_putc`, `lpt_putc` i `cga_putc` i na kraju se `1` ispisuje na monitor.

Proces se ponavlja za ostale karaktere iz `fmt`. Pozivi glavnih funkcija i njihovi argumenti u ostatku koda:
- `cons_putc` sa argumentom  `44`  (`','`)
- `cons_putc` sa argumentom  `32`  (`' '`)
- `cons_putc` sa argumentom  `121` (`'y'`)
- `cons_putc` sa argumentom  `32`  (`' '`)
- `va_arg`    sa argumentima `1`   (`pa` je pointer na `y`) i `unsigned int` (jer printamo `%x` format)
- `cons_putc` sa argumentom  `51`  (`'3'`)
- `cons_putc` sa argumentom  `44`  (`','`)
- `cons_putc` sa argumentom  `32`  (`' '`)
- `cons_putc` sa argumentom  `122` (`'z'`)
- `cons_putc` sa argumentom  `32`  (`' '`)
- `va_arg`    sa argumentima `4`   (`pa` je pointer na `z`) i `int` (jer printamo `%d` format)
- `cons_putc` sa argumentom  `52`  (`'4'`)
- `cons_putc` sa argumentom  `10`  (`'\n'`)


### 4. Run the following code.
``` c
    unsigned int i = 0x00646c72;
    cprintf("H%x Wo%s", 57616, &i);
```
#### What is the output? Explain how this output is arrived at in the step-by-step manner of the previous exercise.
#### The output depends on that fact that the x86 is little-endian. If the x86 were instead big-endian what would you set i to in order to yield the same output? Would you need to change 57616 to a different value?

Kao rezultat izvršenja ispisuje se `He110 World`. 

Vrijednost `57616` u heksadecimalnom formatu je `e110`, pa to objašnjava `He110` dio ispisa. 
Dalje, broj `0x00646c72` se tretira kao niz karaktera, jer je korišten format `%s`. 
Zbog činjenice da je x86 little-endian, broj `0x00646c72` će u memoriji biti poredan tako da je `0x72` na najnižoj adresi, 
zatim `0x6c`, zatim `0x64` i na kraju `0x00` je na najvišoj adresi.
Budući da kada se koristi `%s` format `cprintf` printa karakter po karakter od proslijeđene adrese sve dok ne dođe do `\0` (odnosno `0x0`), 
na ekran će se ispisati `r` (ASCII `0x72`), `l` (ASCII `0x6c`), `d` (ASCII `0x64`) i printanje se zaustavlja na `\0` (ASCII `0x00`).

Da je x86 big-endian, da bi se dobio isti ispis, vrijednost `i` bi trebala biti `0x726c6400`, a `57616` se ne mora mijenjati.


### 5. In the following code, what is going to be printed after 'y='? (note: the answer is not a specific value.) Why does this happen?
``` c
    cprintf("x=%d y=%d", 3);
```

Nakon `y=` će se ispisati random vrijednost, odnosno ispisat će se vrijednost koja se nalazi nakon `3` u memoriji. 
Funkcija `cprintf` očekuje dva argumenta zbog format string-a, a u njenom pozivu je proslijeđen samo jedan. 
Funkcija `cprintf` će se svejedno pročitati memoriju nakon `3`, gdje očekuje drugi argument, i ispisat će šta god se tamo nalazi. 
Budući da nema nikakve garancije šta će biti u tom dijelu memorije, ovo je nedefinisano ponašanje.

### 6. Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declaration order, so that the last argument is pushed last. How would you have to change cprintf or its interface so that it would still be possible to pass it a variable number of arguments? 

Ovaj problem bi se mogao riješiti na tri načina.

Primjer poziva `cprintf` sa trenutnom calling convencijom: \
`cprintf(fmt, arg1, arg2, ..., argn)` \
gdje je `fmt` format string, a `arg1, arg2, ..., argn` su prvi, drugi, ..., n-ti argument, respektivno.

**Prvi način** (_najjednostavniji za implementirati_) \
Interface `cprintf` bi se morao promijeniti tako da se svi argumenti navode u obrnutom redoslijedu.
Ukoliko bi format string i dalje bio prvi parametar `cprintf`, ne bi bilo moguće odrediti gdje se format string nalazi, 
jer `cprintf` ne zna koliko argumenata joj je proslijeđeno, niti veličinu (tip) argumenata (jer je to zapisano u format stringu). 
Ukoliko bi format string bio zadnji argument, bio bi prvi argument od dna stacka, i `cprintf` može raditi na gotovo isti način kao i sada, uz manje izmjene. 

Primjer poziva: \
`cprintf(argn, ..., arg2, arg1, fmt)`

**Drugi način** (_najelegantniji za korisnika_) \
Drugi način je veoma sličan prvom. 
Umjesto da se svi argumenti navode u obrnutom redoslijedu, mogao bi se samo format string navodi kao zadnji argument, a ostali kao i sada. 
Ovo bi radilo zato jer je moguće izračunati gdje su ostali argumenti u memoriji na osnovu format stringa, 
a budući da je format string zadnji argument, `cprintf` zna gdje je on u memoriji.

Primjer poziva: \
`cprintf(arg1, arg2, ..., argn, fmt)`

**Treći način** (_tehnički moguć, ali najgori_) \
Bilo bi moguće napraviti da se `cprintf` poziva na isti način kao i sada, ali da se kao zadnji argument proslijedi suma veličina svih ostalih argumenata u memoriji. 
Jasno, ovaj način je nepraktičan i efektivno se svodi na drugi način, ali je dovoljno različit da se navede zasebno.

Primjer poziva: \
`cprintf(fmt, arg1, arg2, ..., argn, sizeof(arg1) + sizeof(arg2) + sizeof(...) + sizeof(argn))`


## Challenge
Dodana podršku za tekst u boji funkciji `cprintf`. Izmišljena je nova sintaksa. 
Tekst u boji se dodaje tako što se sa `$$` označi da naredni tekst želimo da bude u boji, 
a nakon toga se navodi šifra boje (broj ili karakteri od 'A' do 'F' (isključivo velika slova)). 
Ukoliko se navede jedna cifra posle `$$` obojat će se samo tekst, 
a ako se navedu dvije cifre posle `$$` obojat će se i tekst i pozadina iza teksta.
Kraj bojanja se označava sa `$$`. Ukoliko se bojanje ne zatvori cijeli ostatak string literala će biti obojen navedenom bojom. Default boja se vraća pri izlazku iz funkcije.

Primjer dodavanja boje teksta:
``` c
cprintf("$$1int  -> %d$$ | "
	    "$$2hex  -> %x$$ | "
	    "$$3oct  -> %o$$ | "
	    "$$4char -> %c$$ | "
	    "$$5str  -> %s$$ | "
	    "$$6uint -> %u$$ | "
	    "$$8pad  -> %3d$$ | "
	    "$$9ptr  -> %p$$ | "
	    "$$None$$ | "
	    "$$1Rest...\n",
	    1, 0x2, 03, '4', "5", -6, x, &x);
```

Primjer dodavanja boje teksta i pozadine:
``` c
cprintf("$$00bg -> 0$$ | "
	    "$$10bg -> 1$$ | "
        "$$20bg -> 2$$ | "
        "$$30bg -> 3$$ | "
        "$$40bg -> 4$$ | "
        "$$50bg -> 5$$ | "
        "$$60bg -> 6$$ | "
        "$$70bg -> 7$$ | "
        "$$80bg -> 8$$ | "
        "$$90bg -> 9$$ | "
        "$$A0bg -> A$$ | "
        "$$B0bg -> B$$ | "
        "$$C0bg -> C$$ | "
        "$$D0bg -> D$$ | "
        "$$E0bg -> E$$ | "
        "$$F0bg -> F$$\n");
```

_Najvjerovatnije ću se nakon predavanja laba vratiti na ovaj challenge te (pokušati) implementirati boje na način kako to radi_ `printf`.


# Stack

## Exercise 9
Kernel inicijalizira stack u memoriji nakon koda u `.data` sekciji u fajlu [`entry.S`](../kern/entry.S). 
Stack se inicijalizira direktivom `.space KSTKSIZE`. 
Varijable `KSTKSIZE` je definisana u [`memlayout.h`](../inc/memlayout.h) kao `(8 * PGSIZE)` iz čega se može zaključiti da je stack veličine 8 stranica.
Veličina stranice (`PGSIZE`) je definisana u [`mmu.h`](../inc/mmu.h) kao `4096` iz čega se može zaključiti da je veličina stranice 4kB. 
Dakle, kernel stack je velik 32kB. 

Stack pointer (`%esp`) pokazuje na vrh (najvišu adresu) ovog dijela memorije, 
konkretno na adresu `0xf0111000` (pročitana instrukcija iz `kernel.asm` i vrijednost `%esp` potvrđena koristeći GDB).

Relevantan dio koda iz `kernel.asm`:
``` asm
	# Set the stack pointer
	movl	$(bootstacktop),%esp
f0100034:	bc 00 10 11 f0       	mov    $0xf0111000,%esp
```


## Exercise 10
Funkcija `test_backtrace` se nalazi na adresi `0xf0100040`.
Između poziva `test_backtrace` i sljedećeg poziva `test_backtrace` alocira se 32B stacka, odnosno 8 4-bajtnih riječi (wordova), i to:
- `%ebp` - adresa početka stack framea caller funkcije
- `%ebx` - pohranjuje vrijednost registra jer je prezervirani registar
- prazan prostor
- prazan prostor
- prazan prostor
- drugi argument sljedeće funkcije koja se poziva (`cprintf`), vrijednost argumenta (`x`) funkcije `test_backtrace`
- prvi argument sljedeće funkcije koja se poziva (`cprintf`), pointer na format string `"entering test_backtrace %d\n"`
- povratna adresa iz funkcije koju call instrukcija implicitno pusha na stack

Prazan prostor se dodaje zbog pozivanja funkcije `cprintf`.

Ispis `mon_backtrace`:
```
Stack backtrace:
  ebp f0110f18  eip f010008f  args 00000000 00000000 00000000 00000000 f0100943
  ebp f0110f38  eip f0100068  args 00000000 00000001 f0110f78 00000000 f0100943
  ebp f0110f58  eip f0100068  args 00000001 00000002 f0110f98 00000000 f0100943
  ebp f0110f78  eip f0100068  args 00000002 00000003 f0110fb8 00000000 f0100943
  ebp f0110f98  eip f0100068  args 00000003 00000004 00000000 00000000 00000000
  ebp f0110fb8  eip f0100068  args 00000004 00000005 00000000 000100b4 000100b4
  ebp f0110fd8  eip f01000e0  args 00000005 00001aac 00000640 00000000 00000000
  ebp f0110ff8  eip f010003e  args 00112021 00000000 00000000 00000000 00000000
```

#### The return instruction pointer typically points to the instruction after the call instruction (why?).
Ako bi povratna adresa bila na call instrukciju, pri povratku iz funkcije bi se ponovo izvršila ta ista call instrukcija. 
Rezultat toga je efektivno beskonačna petlja. Zbog toga povratna vrijednost pokazuje na instrukciju posle call instrukcije.

#### Why can't the backtrace code detect how many arguments there actually are? How could this limitation be fixed?
Nema načina da se na osnovu `%ebp` i `%eip` odredi broj argumenta na stacku. 
Odnosno nema informacije gdje argumenti počinju na stacku niti koliko ih ima, poznato je samo gdje se argumenti završavaju. 
Zbog toga `mon_backtrace` ne može odrediti koliko argumenata funkcija uzima. 
Ova limitacija bi se mogla prevazići ukoliko bi se na stack kao zadnji argument proslijeđivao broj argumenata koje funkcija uzima.

## Exercise 11

``` c
#define BT_ARG_NUM 5 // number of arguments mon_backtrace prints

int mon_backtrace(int argc, char** argv, struct Trapframe* tf)
{
  uint32_t args[BT_ARG_NUM];
  uint32_t* ebp = (uint32_t*)read_ebp();
  uint32_t eip = ebp[1];

  cprintf("Stack backtrace:\n");

  while (ebp)
  {
    // read arguments from stack into args
    for (int i = 0; i < BT_ARG_NUM; ++i)
      args[i] = ebp[2 + i];

    cprintf("  ebp %08x  eip %08x  args", ebp, eip);
    for (int i = 0; i < BT_ARG_NUM; ++i)
      cprintf(" %08x", args[i]);
    cputchar('\n');

    eip = ebp[1];
    ebp = (uint32_t*)*ebp;
  }

  return 0;
}
```

## Exercise 12

#### In debuginfo_eip, where do __STAB_* come from?
`__STAB_*` su varijable koje pravi linker skripta [`kernel.ld`](../kern/kernel.ld) i označavaju početak i kraj `.stab` i `.stabstr` sekcija kernela (`__STAB_BEGIN__`, `__STAB_END__`, `__STABSTR_BEGIN__` i `__STABSTR_END_` respektivno). 

Relevantan kod iz linker skripte `kernel.ld`:
``` ld
	/* Include debugging information in kernel memory */
	.stab : {
		PROVIDE(__STAB_BEGIN__ = .);
		*(.stab);
		PROVIDE(__STAB_END__ = .);
		BYTE(0)		/* Force the linker to allocate space
				   for this section */
	}

	.stabstr : {
		PROVIDE(__STABSTR_BEGIN__ = .);
		*(.stabstr);
		PROVIDE(__STABSTR_END__ = .);
		BYTE(0)		/* Force the linker to allocate space
				   for this section */
	}
```

Izvršavanjem `objdump -h obj/kern/kernel` dobija se:
```
obj/kern/kernel:     file format elf32-i386

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00001a4d  f0100000  00100000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rodata       0000077c  f0101a60  00101a60  00002a60  2**5
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         00004645  f01021dc  001021dc  000031dc  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .stabstr      00001a20  f0106821  00106821  00007821  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .note.gnu.property 0000001c  f0108244  00108244  00009244  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .data         0000a304  f0109000  00109000  0000a000  2**12
                  CONTENTS, ALLOC, LOAD, DATA
  6 .bss          00000648  f0113320  00113320  00014320  2**5
                  CONTENTS, ALLOC, LOAD, DATA
  7 .comment      00000011  00000000  00000000  00014968  2**0
                  CONTENTS, READONLY
```

Bitne sekcije za ovaj zadatak su `.stab` i `.stabstr`. 
U `.stab` sekciji se nalaze metapodaci koji će se koristiti za debagiranje, 
a u `.stabstr` sekciji se nalaze stringovi koji opisuju korespondirajuće metapodatke iz `.stab` sekcije (npr. ime fajla i funkcije).

Izvršavanjem `objdump -G obj/kern/kernel` dobija se:
```
obj/kern/kernel:     file format elf32-i386

Contents of .stab section:

Symnum n_type n_othr n_desc n_value  n_strx String

-1     HdrSym 0      1498   00001a1f 1     
0      SO     0      0      f0100000 1      {standard input}
1      SOL    0      0      f010000c 18     kern/entry.S
2      SLINE  0      44     f010000c 0      
3      SLINE  0      57     f0100015 0      
4      SLINE  0      58     f010001a 0      
5      SLINE  0      60     f010001d 0      
6      SLINE  0      61     f0100020 0      
7      SLINE  0      62     f0100025 0      
8      SLINE  0      67     f0100028 0      
9      SLINE  0      68     f010002d 0      
10     SLINE  0      74     f010002f 0      
11     SLINE  0      77     f0100034 0      
12     SLINE  0      80     f0100039 0      
13     SLINE  0      83     f010003e 0      
14     SO     0      2      f0100040 31     kern/entrypgdir.c
15     OPT    0      0      00000000 49     gcc2_compiled.
                    ...
110    FUN    0      0      f0100040 2988   test_backtrace:F(0,25)
111    PSYM   0      0      00000008 3011   x:p(0,1)
112    SLINE  0      12     00000000 0      
113    SLINE  0      13     0000000a 0      
114    SLINE  0      14     00000015 0      
115    SLINE  0      15     0000001c 0      
116    SLINE  0      18     0000002b 0      
117    SLINE  0      19     00000039 0      
118    SLINE  0      17     00000041 0      
119    RSYM   0      0      00000003 3020   x:r(0,1)
                    ...
455    SO     0      2      f010068a 3876   kern/monitor.c
456    OPT    0      0      00000000 49     gcc2_compiled.
                    ...
514    FUN    0      0      f0100779 4293   mon_backtrace:F(0,1)
515    PSYM   0      0      00000008 4185   argc:p(0,1)
516    PSYM   0      0      0000000c 4269   argv:p(0,29)
517    PSYM   0      0      00000010 4282   tf:p(0,30)
518    SLINE  0      59     00000000 0      
                    ...
1493   RSYM   0      0      00000002 6676   dig:r(0,1)
1494   LBRAC  0      0      0000007c 0      
1495   RBRAC  0      0      000000c1 0      
1496   RBRAC  0      0      000000da 0      
1497   SO     0      0      f01017e9 0 
```

Kolona `Symnum` označava redni broj simbola unutar `.stab` sekcija (označava i broj reda u datom ispisu). \
Kolona `n_type` označava tip simbola, npr. `SO` je source file, `FUN` je funkcija, `SLINE` je broj linije koda, itd. \
Kolona `String` opisuje dati red i čita se iz `.stabstr` sekcije, npr. `445` može se zaključiti da red `445` predstavlja source file `kern/monitor.c`. \
Kolona `n_value` predstavlja adresu, npr. u redu `514` može se zaključiti da je funkcija `mon_backtrace` na adresi `0xf0100779`. \
Kolona `n_desc` predstavlja dodatni opis, npr. u redu `518` možemo zaključiti da `59` predstavlja broj linije koda, jer je simbol tipa `SLINE`. \
Kolona `n_strx` predstavlja broj bajta odakle dati string počinje u `.stabstr` sekciji.

Kompajliranjem `init.c` sa `gcc -pipe -nostdinc -O2 -fno-builtin -I. -MD -Wall -Wno-format -DJOS_KERNEL -gstabs -c -S kern/init.c`, pogledom u dobijeni `init.s` dobija se:
``` asm
	.file	"init.c"
	.stabs	"kern/init.c",100,0,2,.Ltext0
	.text
.Ltext0:
	.stabs	"gcc2_compiled.",60,0,0,0
	.stabs	"int:t(0,1)=r(0,1);-2147483648;2147483647;",128,0,0,0
	.stabs	"char:t(0,2)=r(0,2);0;127;",128,0,0,0
	.stabs	"long int:t(0,3)=r(0,3);-9223372036854775808;9223372036854775807;",128,0,0,0
	.stabs	"unsigned int:t(0,4)=r(0,4);0;4294967295;",128,0,0,0
                    ...
.LC0:
	.string	"entering test_backtrace %d\n"
.LC1:
	.string	"leaving test_backtrace %d\n"
	.text
	.p2align 4
	.stabs	"test_backtrace:F(0,25)",36,0,0,test_backtrace
	.stabs	"x:P(0,1)",64,0,0,6
	.globl	test_backtrace
	.type	test_backtrace, @function
test_backtrace:
	.stabn	68,0,13,.LM0-.LFBB1
.LM0:
.LFBB1:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	.stabn	68,0,14,.LM1-.LFBB1
.LM1:
	movl	%edi, %esi
	.stabn	68,0,13,.LM2-.LFBB1
                    ...
```

Iz čega se vidi kako se popunjavaju `.stab` i `.stabstr` sekcije.

Na osnovu ovih informacija može se poboljšati implementacija funkcija `mon_backtrace` tako da ispisuje ime source fajla, ime funkcije, broj linije i broj bajta poziva funkcije:
``` c
int mon_backtrace(int argc, char** argv, struct Trapframe* tf)
{
  struct Eipdebuginfo eipinfo;

                ...

  while (ebp)
  {
                ...
    // print function info
    cprintf("\t\t%s:%d: %.*s+%d\n",
      eipinfo.eip_file,
      eipinfo.eip_line,
      eipinfo.eip_fn_namelen,
      eipinfo.eip_fn_name,
      (eip - eipinfo.eip_fn_addr));
                ...
  }

  return 0;
}
```

Ispis poboljšane `mon_backtrace` funkcije:
```
Stack backtrace:
  ebp f0110f18  eip f010008f  args 00000000 00000000 00000000 00000000 f010096b
          kern/init.c:17: test_backtrace+79
  ebp f0110f38  eip f0100068  args 00000000 00000001 f0110f78 00000000 f010096b
          kern/init.c:15: test_backtrace+40
  ebp f0110f58  eip f0100068  args 00000001 00000002 f0110f98 00000000 f010096b
          kern/init.c:15: test_backtrace+40
  ebp f0110f78  eip f0100068  args 00000002 00000003 f0110fb8 00000000 f010096b
          kern/init.c:15: test_backtrace+40
  ebp f0110f98  eip f0100068  args 00000003 00000004 00000000 00000000 00000000
          kern/init.c:15: test_backtrace+40
  ebp f0110fb8  eip f0100068  args 00000004 00000005 00000000 000100b4 000100b4
          kern/init.c:15: test_backtrace+40
  ebp f0110fd8  eip f01000e0  args 00000005 00001aac 00000640 00000000 00000000
          kern/init.c:38: i386_init+76
  ebp f0110ff8  eip f010003e  args 00112021 00000000 00000000 00000000 00000000
          kern/entry.S:83: <unknown>+0
```

