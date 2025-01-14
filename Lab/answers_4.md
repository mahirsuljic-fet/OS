<div align='center'><h1 align='center'>Part A: Multiprocessor Support and Cooperative Multitasking</h1></div>

# Multiprocessor Support

## Exercise 1
Funkcija `mmio_map_region` se koristi za mapiranje fizičkih adresa koje su fizički preusmjerene 
na neke druge uređaje u dio virtuelne memorije od `MMIOBASE` do `MMIOLIM`.
Implementirana je u fajlu [`pmap.c`](../kern/pmap.c) kao wrapper oko funkcije `boot_map_region`:
``` c
void* mmio_map_region(physaddr_t pa, size_t size)
{
  static uintptr_t base = MMIOBASE;

  uintptr_t last_map_vaddr; // end of region which is currently getting mapped
  uintptr_t old_base;       // value of base before current mapping

  size = ROUNDUP(size, PGSIZE); // align size to page
  last_map_vaddr = base + size; // ok because base is initially page aligned (MMIOBASE)

  // sanity check
  if (last_map_vaddr > MMIOLIM)
    panic("mmio_map_region: reached MMIOLIM");

  // mapping
  boot_map_region(kern_pgdir, base, size, pa, PTE_W | PTE_PCD | PTE_PWT);

  old_base = base;
  base += size;

  return (void*)old_base;
}
```

`pa` predstavlja fizičku adresu koja se mapira.
Pristupom toj adresi se najčešće pristupa registrima nekog uređaja kao što je npr. LAPIC.

Unutar funkcije je definisana statička varijabla `base` koja je inicijalizirana na `MMIOBASE`
i predstavlja prvu adresu koja nije mapirana, iz dijela virtuelnog adresnog prostora između `MMIOBASE` i `MMIOLIM`.
Ovo je vrlo slično onome što radi funkcija `boot_alloc`.

Nije moguće mapirati proizvoljnu količinu memorije, nego se mapiranje uvijek vrši po stranicama.
Zbog toga se količina memorije koju želimo mapirati (`size`) zaokružuje na `PGSIZE`, i to prema "gore" pomoću makroa `ROUNDUP`.

`base` ima inicijalnu vrijednost `MMIOBASE`, što je poravnato na veličinu stranice (`PGSIZE`).
Budući da su `base` i `size` uvijek poravnati na `PGSIZE`, njihov zbir će uvijek biti poravnat na `PGSIZE`.
Zbog toga se ok postaviti vrijednost `last_map_vaddr` i novu vrijednost `base` na način kako je urađeno.

`MMIOLIM` predstavlja zadnju adresu virtuelnog memorijskog prostora za koju je predviđeno da se mapira neki uređaj.
Ne bi se smjelo desiti da se uređaji mapiraju iznad dijela memorije predviđen za to, pa se u tom slučaju poziva `panic`.

Glavni dio funkcije je mapiranje.
Mapiranje se delegira funkciji `boot_map_region`.
Kao page directory se koristi kernelov (`kern_pgdir`), za virtuelnu adresu se koristi `base`.
Za veličinu se prosljeđuje `size`, fizička adresa je data kao argument za `mmio_map_region`.
Za permisije se koristi `PTE_W` jer želimo imati mogućnost pisanja u registre od mapiranih uređaja,
međutim, ovdje se također prosljeđuju još dva flag-a `PTE_PCD` i `PTE_PWT`, koji govore procesoru da ne kešira tu stranicu.

Konačno, funkcija vraća prvu adresu iz novo-mapiranog opsega.


# Application Processor Bootstrap

## Exercise 2
Ispod je pod `5)` označen modifikovani dio funkcije `page_init` iz [`pmap.c`](../kern/pmap.c):
``` c
void page_init(void)
{
  size_t i;
                ...
  // 2)
  for (i = 1; i < npages_basemem; ++i)
  {
    ////////////////////////////////////////////////////////
    // 5)
    physaddr_t current_page_pa = page2pa(&pages[i]);
    if (current_page_pa == ROUNDDOWN(MPENTRY_PADDR, PGSIZE))
    {
      ++pages[i].pp_ref;
    }
    ////////////////////////////////////////////////////////
    // 2)
    else
    {
      pages[i].pp_link = page_free_list;
      page_free_list = &pages[i];
    }
  }
                ...
}
```
Adresa `MPENTRY_PADDR` se nalazi u base dijelu memorije, za čiju inicijalizaciju stranica je bio zadužen dio `2)` iz predhodnih lab-ova, 
pa ga je potrebno modifikovati tako da "preskoči" stranicu koja sadrži `MPENTRY_PADDR`.
Pomoću funkcije `page2pa` se može odrediti fizička adresa date stranice.
Ta fizička adresa se spremi u `current_page_pa` i zatim poredi sa `MPENTRY_PADDR`.
Ako je `MPENTRY_PADDR` u trenutnoj stranici, tada se samo `pp_ref` te stranice inkrementira, kao znak da se ova stranica koristi,
što u ovom slučaju zapravo znači da se ova stranica nikada neće koristiti, odnosno dodijeliti nekom programu na korištenje.
U suprotnom se ta stranica dodaje u listu slobodnih stranica, kao i prethodno.

Zašto se koristi `ROUNDDOWN` na `PGSIZE` za `MPENTRY_PADDR`? \
Za trenutnu konfiguraciju ovo nije potrebno zato jer `MPENTRY_PADDR` ima vrijednost `0x7000` koja je poravnata na `PGSIZE`.
Međutim, kada `MPENTRY_PADDR` ne bi bila poravnata na `PGSIZE` (npr. da je `0x7800`) i ako se ne koristi `ROUNDDOWN`,
izraz unutar `if`-a nikada neće vratiti tačno, jer je `current_page_pa` poravnato na `PGSIZE`, a `MPENTRY_PADDR` nije.
U tom slučaju će se i stranica sa adresom `MPENTRY_PADDR` dodati u listu slobodnih stranica i postoji mogućnost da se dodijeli nekom okruženju.
Dakle, `ROUNDDOWN` osigurava da se stranica koja sadrži adresu `MPENTRY_PADDR` "preskoči", čak i ako `MPENTRY_PADDR` nije poravnata na `PGSIZE`.


## Question 1
#### Compare `kern/mpentry.S` side by side with `boot/boot.S`. Bearing in mind that `kern/mpentry.S` is compiled and linked to run above `KERNBASE` just like everything else in the kernel, what is the purpose of macro `MPBOOTPHYS`? Why is it necessary in `kern/mpentry.S` but not in `boot/boot.S`? In other words, what could go wrong if it were omitted in `kern/mpentry.S`?

Uloga makroa `MPBOOTPHYS` je da mapira ("prevede") adrese linkane iznad `KERNBASE` u fizičke adrese tek iznad `MPENTRY_PADDR` koje se mogu korsititi u asembleru.
Pogledajmo gdje se koristi `MPBOOTPHYS`:
``` asm
.code16           
.globl mpentry_start
mpentry_start:
	cli            

	xorw    %ax, %ax
	movw    %ax, %ds
	movw    %ax, %es
	movw    %ax, %ss

	lgdt    MPBOOTPHYS(gdtdesc)
	movl    %cr0, %eax
	orl     $CR0_PE, %eax
	movl    %eax, %cr0

	ljmpl   $(PROT_MODE_CSEG), $(MPBOOTPHYS(start32))
```
Koristi se dakle dok procesor izvršava 16-bitne instrukcije.
Razlog zašto [`mpentry.S`](../kern/mpentry.S) mora koristiti ovaj makro, a [`boot.S`](../boot/boot.S) ne mora je zbog različitih link adresa.
[`boot.S`](../boot/boot.S) je linkan na `0x00007c00`, dok je [`mpentry.S`](../kern/mpentry.S) unutar kernela.

Ako pogledamo disasembliran objektni fajl u koji se kompajlira [`boot.S`](../boot/boot.S) dobijamo:
``` asm
00007c00 <start>:
```
iz čega se jasno vidi da je label `start`, koji predstavlja entry point bootloadera, linkan na adresu `0x00007c00`.

Ako pogledamo disasemblirani kernel dobijamo:
``` asm
f01064e8 <mpentry_start>:
```
iz čega se jasno vidi da je label `mpentry_start`, koji predstavlja entry point programa koji inicijalizira AP jezgre, na adresi `0xf01064e8`.

Međutim, zbog čega je tačno ovo problem?

Problem je u tome što procesor dok izvršava 16-bitne instrukcije ne može pravilno procesirati adrese preko 1MB, odnosno tačnije veće od 20b.
U stvari, budući da makro `MPBOOTPHYS` koristimo kako bi učitali GDT, za šta koristimo 16-bitnu instrukciju `lgdt`, 
linker će prijaviti grešku jer je `gdtdesc` label linkan na 32-bitnu adresu, a ovdje je pokušavamo "strpati" u 16 bita.
Što se tiče drugog korištenja makroa `MPBOOTPHYS`, za `start32`.
U ovom slučaju koristimo instrukciju `ljmpl` koja prima dva argumenta, vrijednost za `%cs` i vrijednost za `%eip`.
Ako pokušamo koristiti direktno adresu na koju je `start32` linkan (bez `MPBOOTPHYS`), procesor će pokušati nastaviti izvršavati kod sa pogrešne adrese.

Ovo možemo i provjeriti. Fokusirajmo se na sljedeći dio koda iz [`mpentry.S`](../kern/mpentry.S):
``` asm
.code16           
.globl mpentry_start
mpentry_start:
            ...
	lgdt    MPBOOTPHYS(gdtdesc)
            ...
	ljmpl   $(PROT_MODE_CSEG), $(MPBOOTPHYS(start32))
            ...
```

Ako izbrišemo obje instance korištenja makroa `MPBOOTPHYS`:
``` asm
.code16           
.globl mpentry_start
mpentry_start:
            ...
	lgdt    gdtdesc
            ...
	ljmpl   $(PROT_MODE_CSEG), $(start32)
            ...
```
i zatim pokušamo kompajlirati i linkati dobijamo linker error:
``` 
+ ld obj/kern/kernel
/nix/store/vfqlryhvm8063hs7ax9k2vb8wmch5v0v-binutils-2.31.1/bin/ld: obj/kern/mpentry.o:kern/mpentry.S:46:(.text+0xc): relocation truncated to fit: R_386_16 against `.text'
make: *** [kern/Makefrag:110: obj/kern/kernel] Error 1
```
što potvrđuje pretpostavku o prvom korištenju `MPBOOTPHYS`.

Dalje, ako izbrišemo samo drugu instancu korištenja `MPBOOTPHYS`:
``` asm
.code16           
.globl mpentry_start
mpentry_start:
            ...
	lgdt    MPBOOTPHYS(gdtdesc)
            ...
	ljmpl   $(PROT_MODE_CSEG), $(start32)
            ...
```
program kompajlira, ali se pri izvršenju zaustavi u beskonačnoj petlji i sistem se "zamrzne".
Pokušajmo pomoću GDB analizirati šta se desi.

Za ovo će biti potrebno par adresa iz disasembliranog kernela:
``` asm
f0106a6a <lapic_startap>:
           ...           
f0106aee:	e8 e3 fd ff ff       	call   f01068cf <lapicw>
           ...           
f0106b11:	c3   ret    
```

Funkcija `lapic_startap` je zadužena za buđenje AP jezgri.
Adresa `0xf0106a6a` predstavlja adresu prve instrukcije funkcije `lapic_startap`, a adresa `0xf0106b11` zadnju (`ret`).
Adresa `0xf0106aee` predstavlja adresu call instrukcije nakon koje se dato AP jezgro probudi.
Za ove potrebe sasvim je dovoljna adresa `0xf0106b11`, ali će se koristiti i `0xf0106a6a`, dok `0xf0106aee` neće.

U GDB postavimo breakpointe na pomenute adrese:
``` console
(gdb) break *0xf0106a6a
Breakpoint 1 at 0xf0106a6a: file kern/lapic.c, line 138.

(gdb) break *0xf0106b11
Breakpoint 2 at 0xf0106b11: file kern/lapic.c, line 170.
```

Zatim pustimo BSP jezgru da izvršava kod dok ne dođe do funkcije `lapic_startap`:
``` console
(gdb) continue
Continuing.
The target architecture is assumed to be i386
=> 0xf0106a6a <lapic_startap>:  push   %ebp

Thread 1 hit Breakpoint 1, lapic_startap (apicid=1, addr=28672) at kern/lapic.c:138
138     {
```

Pomoću `info thread` mogu se vidjeti stanja svih jezgri koje QEMU koristi.
U ovom slučaju QEMU je pokrenut sa 4 jezgra, od kojih je jezgro sa Id 1 BSP i izvršava kod iz `lapic_startap`,
a ostala tri jezgra su zaustavljena.
``` console
(gdb) info thread
  Id   Target Id                    Frame
* 1    Thread 1.1 (CPU#0 [running]) lapic_startap (apicid=1, addr=28672) at kern/lapic.c:138
  2    Thread 1.2 (CPU#1 [halted ]) 0x000fd0a9 in ?? ()
  3    Thread 1.3 (CPU#2 [halted ]) 0x000fd0a9 in ?? ()
  4    Thread 1.4 (CPU#3 [halted ]) 0x000fd0a9 in ?? ()
```

Puštanjem BSP jezgra da nastavlja izvršavanje `lapic_startap` dolazi do kraja te funkcije, pri čemu bi se neko dugo, AP, jezgro trebalo probuditi.
``` console
(gdb) continue
Continuing.
=> 0xf0106b11 <lapic_startap+167>:      ret

Thread 1 hit Breakpoint 2, 0xf0106b11 in lapic_startap (apicid=1204257, addr=0) at kern/lapic.c:170
170     }
```

Provjerom pomoću `info thread` se vidi da je jezgro sa Id 2 zaista probuđeno i počinje izvršavati neki kod.
``` console
(gdb) info thread
  Id   Target Id                    Frame
* 1    Thread 1.1 (CPU#0 [running]) 0xf0106b11 in lapic_startap (apicid=1204257, addr=0) at kern/lapic.c:170
  2    Thread 1.2 (CPU#1 [running]) 0x00000018 in ?? ()
  3    Thread 1.3 (CPU#2 [halted ]) 0x000fd0a9 in ?? ()
  4    Thread 1.4 (CPU#3 [halted ]) 0x000fd0a9 in ?? ()
```

Prebacimo se na jezgri sa Id 2 pomoću `thread 2`
``` console
(gdb) thread 2
[Switching to thread 2 (Thread 1.2)]
#0  0x00000018 in ?? ()
```

Pomoću `info thread` može se vidjeti da sada zaista posmatramo jezgro sa Id 2, jer pored Id ima `*`.
``` console
(gdb) info thread
  Id   Target Id                    Frame
  1    Thread 1.1 (CPU#0 [running]) 0xf0106b11 in lapic_startap (apicid=1204257, addr=0) at kern/lapic.c:170
* 2    Thread 1.2 (CPU#1 [running]) 0x00000018 in ?? ()
  3    Thread 1.3 (CPU#2 [halted ]) 0x000fd0a9 in ?? ()
  4    Thread 1.4 (CPU#3 [halted ]) 0x000fd0a9 in ?? ()
```

AP jezgro dolazi do instrukcije `ljmp`, pri čemu se može vidjeti link adresa od `start32` (`0xf0106508`) u argumentima instrukcije.
``` console
(gdb)
[ 700:  18]    0x7018:  ljmpw  $0xf010,$0x6508
0x00000018 in ?? ()
```

Izvršavanjem instrukcije `ljmp` dobija se error pri pristupu memoriji.
``` console
(gdb)
The target architecture is assumed to be i386
=> 0xf0106508 <start32>:        Error while running hook_stop:
Cannot access memory at address 0xf0106508
55              movw    $(PROT_MODE_DSEG), %ax
```
procesor dalje je zarobljen u jer ne može pristupiti memoriji, te završiti svoj startup proces.


# Per-CPU State and Initialization

## Exercise 3
Svi kernel stackovi se nalaze ispod adrese `KSTACKTOP`.
Svaki kernel stack je veličine `KSTKSIZE` bajti.
Odma ispod `KSTACKTOP` je kernel stack od jezgra CPU 0, ispod njega se nalazi kernel stack od jezgra CPU 1, 
ispod njega od CPU 2, itd. za svako jezgro.
Ispod svakog kernel stacka je nemapirani dio memorije koji je veličine `KSTKGAP` bajti koji razdvaja kernel stackove.
Ova "praznina" je potrebna kako jedan kernel stack ne bi slučajno pristupio drugom kernel stack-u.
Ako kernel stack jezgra CPU 0 popuni cijeli svoj stack, sljedećim pristupom memoriji pristupa nemapiranom dijelu memorije i time proizvodi iznimku.
Ako ne bi bilo ove "praznine", tada bi kernel stack jezgra CPU 0 počelo pisati preko podataka sa kernel stacka jezgra CPU 1.

Uzimajući ovo u obzir, u fajlu [`pmap.c`](../kern/pmap.c) je implementirana funkcija `mem_init_mp`:
``` c
static void mem_init_mp(void)
{
  for (int i = 0; i < NCPU; ++i)
  {
    int offset = i * (KSTKSIZE + KSTKGAP); // "distance" between KSTACKTOP and top of CPU i's stack
    int stacktop = KSTACKTOP - offset;     // top of CPU i's stack
    boot_map_region(kern_pgdir, stacktop - KSTKSIZE, KSTKSIZE, PADDR(percpu_kstacks[i]), PTE_W);
  }
}
```
Zadatak ove funkcije je da mapira kernel stack za svako jezgro.
Za mapiranje se koristi funkcije `boot_map_region`, a njeni argumenti su sljedeći:
- za page directory se koristi kernelov `kern_pgdir`
- virtuelna adresa je dno kernel stacka datog jezgra
- veličina je `KSTKSIZE`
- fizička adresa je fizička adresa `i`-tog elementa iz niza `percpu_kstacks`
- permisije su `PTE_W`, jer želimo pisati na stack

`percpu_kstacks` je globalni neinicijalizirani niz od `NCPU` elemenata po `KSTKSIZE` bajti i predstavlja niz kernel stackova.
Ovim možemo zaključiti da se kernel stackovi nalaze u `.bss` sekciji kernela. \
`offset` je količina memorije između `KSTACKTOP` i vrha `i`-tog kernel stacka. \
`stacktop` je adresa vrha `i`-tog kernel stacka.
Budući da je `stacktop` vrh stacka, kao argument za virtuelnu adresu u funkciju `boot_map_region` 
se prosljeđuje `stacktop - KSTKSIZE` čime se dobija adresa dna `i`-tog kernel stacka.


## Exercise 4
Globalna varijabla `ts` više nije dovoljna.
Kernel globalne varijable se nalaze u `.bss`, `.data` ili eventualno `.rodata` sekcijama kernela.
Ovu memoriju dijele sve jezgre, tako da bi sve jezgre pristupale istoj varijabli `ts`.
Ovo je problem jer u `ts` se nalazi adresa kernel stacka koji dato jezgro treba koristiti kada tretira prekide.
Ako bi se i dalje koristila globalna varijabla `ts` nastao bi haos, jer bi sva jezgra pokušavala pristupati istom kernel stacku.
Umjesto toga, koristit će se varijabla `cpu_ts`, koja je polje u strukturi `struct CpuInfo` 
(definisana u [`cpu.h`](../kern/cpu.h)) koja predstavlja opis/podatke/stanje datog jezgra.

Postoji globalni niz struktura `struct CpuInfo` pod imenom `cpus` (definisan u [`mpconfig.c`](../kern/mpconfig.c)) koji predstavlja niz stanja svih jezgri.
Pomoću funkcije `cpunum` (definisana u [`lapic.c`](../kern/lapic.c)) se može dobiti id jezgra koje izvrši tu funkciju.
Id jezgra se može iskoristiti da se indeksira niz `cpus`.
Postoji makro `thiscpu` definisan u [`cpu.h`](../kern/cpu.h) koji koristi pomenuto da vrati pointer na trenutno jezgro (`struct CpuInfo` iz `cpus`).

Ispod se nalazi nova implementacija funkcije `trap_init_percpu` iz fajla [`trap.c`](../kern/trap.c):
``` c
void trap_init_percpu(void)
{
  uint8_t cur_cpu_id = thiscpu->cpu_id;

  thiscpu->cpu_ts.ts_esp0 = (uintptr_t)percpu_kstacks[cur_cpu_id] + KSTKSIZE;
  thiscpu->cpu_ts.ts_ss0 = GD_KD;
  thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);

  gdt[(GD_TSS0 >> 3) + cur_cpu_id] = SEG16(STS_T32A, (uint32_t)(&thiscpu->cpu_ts), sizeof(struct Taskstate) - 1, 0);
  gdt[(GD_TSS0 >> 3) + cur_cpu_id].sd_s = 0;

  ltr(GD_TSS0 + (cur_cpu_id << 3));

  // Load the IDT
  lidt(&idt_pd);
}
```
Svaka instanca globalne varijable `ts` se mijenja sa `ts` od trenutnog jezgra, odnosno sa `thiscpu->cpu_ts`.
Za pointere na kernel stackove se koristi globalni niz `percpu_kstacks` koji je korišten i u ***Exercise 3***.
Vrijednost `%ss` ostaje ista (`GD_KD`) i predstavlja selektor za kernel data segment.
Vrijednost za iomb ([iopb](https://wiki.osdev.org/Task_State_Segment)) također se ne mijenja, ostaje na veličini TSS-a.

GDT će sada nešto drugačije izgledati.
U GDT će se nalaziti `NCPU` TSS deskriptora, po jedan za svako jezgro.
Pomoću `(GD_TSS0 >> 3) + cur_cpu_id` se indeksira GDT kako bi došli do mjesta gdje 
treba biti TSS deskriptora trenutnog jezgra i tu napravimo TSS deskriptor pomoću makroa `SEG16`.

Na kraju učitamo TSS deskriptor trenutnog jezgra u `%tr` trenutnog jezgra pomoću funkcije `ltr` koja je implementirana u asembleru u fajlu [`x86`](../inc/x86.h).
Za lakše razumijevanje, dio koda `GD_TSS0 + (cur_cpu_id << 3)` se može zapisati kao `GD_TSS0 + cur_cpu_id * sizeof(struct Segdesc)`.
Struktura `struct Segdesc` predstavlja deskriptor.
Ovim praktično govorimo *kreni od TSS deskriptora jezgra 0 (`GD_TSS0`) i pomjeri se za `cur_cpu_id` deskriptora*.
Time dolazimo do TSS desktiptora trenutnog jezgra.


# Locking

## Exercise 5
Big kernel lock je potrebno postaviti na sva mjesta gdje potencijalno više jezgri može pristupati kernelu.
Ta mjesta su navedena u lab-u i ispod je kod u kojem su postavljeni big kernel lockovi na tim mjestima.

- [`init.c`](../kern/init.c)
``` c
void i386_init(void)
{
       ...
  lock_kernel();
  boot_aps();
       ...
}
```

- [`init.c`](../kern/init.c)
``` c
void mp_main(void)
{
       ...
  lock_kernel();
  sched_yield();
}
```

- [`trap.c`](../kern/trap.c)
``` c
void trap(struct Trapframe* tf)
{
            ...
  if ((tf->tf_cs & 3) == 3)
  {
            ...
    lock_kernel(); // <<<<<<<<<<

    // Garbage collect if current enviroment is a zombie
    if (curenv->env_status == ENV_DYING)
    {
      env_free(curenv);
      curenv = NULL;
      sched_yield();
    }
            ...
  }
            ...
}
```

Big kernel lock je potrebno odpustiti kada prelazimo iz kernel u user mode.
To se radi u funkciji `env_run` pomoću funkcije `env_pop_tf`.
Prije toga učitajemo virtuelni adresni prostor od okruženja koje se pokreće promjenom vrijednosti registra `%cr3`.
Budući da je za kernel lock i unlock potreban kernel nivo privilegija, kernel se mora otključati prije učitavanja adresnog prostora od okruženja.
``` c
void env_run(struct Env* e)
{
          ...
  unlock_kernel();

  lcr3(PADDR(e->env_pgdir));
  env_pop_tf(&e->env_tf);
}
```


## Question 2
#### It seems that using the big kernel lock guarantees that only one CPU can run the kernel code at a time. Why do we still need separate kernel stacks for each CPU? Describe a scenario in which using a shared kernel stack will go wrong, even with the protection of the big kernel lock.
Problem sa korištenjem jednog kernel stacka je u tome što svaki procesor pusha trap frame na stack, 
a to se radi neovisno o tome da li je kernel zaključan ili ne, jer jedan dio trap frame-a procesor pusha automatski, 
a drugi se pusha u asembleru u funkciji `_alltraps`.
`_alltraps` poziva `trap` koji konačno dolazi do kernel lock-a.

Uzmimo sljedeći slučaj za primjer.
Jezgro 1 izvršava okruženje 1.
Jezgro 2 izvršava okruženje 2.
Okruženje 1 izazove prekid.
Jezgro 1 pusha dio trap frame-a na stack i broj prekida.
U tom trenutku okruženje 2 izazove neki prekid i pusha dio trap frame-a na stack.
Dalje, jezgro 1 pusha ostatak trap frame-a na stack, poziva funkciju `trap` i zaključa kernel.
Dok se to izvršava, jezgro 2 pusha ostatak trap frame-a na stack, poziva funkciju `trap`, dolazi do kernel lock-a i čeka da se kernel otključa.
Trap frame-ovi na stacku su ispreplitani i jezgra neće moći pravilno nastaviti izvršavanje okruženja, niti će moći pravilno servisirati prekid.


# Round-Robin Scheduling

## Exercise 6
Način na koji round-robin scheduling radi je da skenira sva okruženja tražeći okruženje u RUNNABLE stanju.
Prvo okruženje koje nađe u RUNNABLE stanju treba pokrenuti, te se time ono prebacuje u RUNNING stanje i počinje izvršavati na datom jezgru.
Ako ne nađe niti jedno RUNNABLE okruženje tada će pokušati nastaviti sa izvršavanjem okruženja koje se već izvršavalo da datom jezgru, ako je ono i dalje RUNNING.
U suprotnom poziva se funkcija `sched_halt`.

Slijedi implementacija funkcije `sched_yield` u fajlu [`sched.c`](../kern/sched.c):
``` c
void sched_yield(void)
{
  struct Env* e = curenv ? curenv : &envs[0];
  struct Env* e_initial = e;

  do
  {
    // cycle back to beginning if we get outside of envs array
    if (++e >= &envs[NENV])
      e = &envs[0];

    // run environment if RUNNABLE
    if (e->env_status == ENV_RUNNABLE)
      env_run(e);
  }
  while (e != e_initial); // search until we get to current environment

  // if current environment is still RUNNING then continue running it
  if (curenv && curenv->env_status == ENV_RUNNING)
    env_run(curenv);

  // sched_halt never returns
  sched_halt();
}
```

Ako se do sada ni jedno okruženje nije izvršavalo na datoj jezgri, `curenv` će biti `NULL`.
Varijabla `e` predstavlja pointer na neko okruženje.
Ona se koristi kako bi skenirali kroz sva okruženja, tražeći RUNNABLE okruženje.
Inicijalno, ako `curenv` ima vrijednost `NULL`, tada skeniranje počinje od `envs[0]`, odnosno prvog okruženja iz niza okruženja.
U suprotnom, skeniranje počinje od `curenv`, odnosno okruženja koje se izvršavalo na datom jezgru.
Varijabla `e_initial` služi da zapamtimo od kojeg okruženja je skeniranje početo.

Dalje, u do while petlji se vrši potraga za RUNNABLE okruženjem.
Skeniranje počinje od prvog okruženja nakon `e_initial`.
Ako pointer `e` ode izvan granica niza `envs` (`>= &envs[NENV]`), tada se `e` vrati na prvo okruženje (`envs[0]`).
Ovim se niz `envs` skenira kao ciklični buffer.
Ako je trenutno okruženje `e` RUNNABLE, tada se ono pokreće.
Ako petlja dođe do prvobitnog okruženja `e_initial`, tada se vrši izlaz iz petlje i time prestaje potraga za RUNNABLE okruženjima jer su pregledana sva okruženja.
U tom slučaju, ako okruženje koje je prethodno izvršavano na datom jezgru (`curenv`) postoji (nije `NULL`) i ako je i dalje u RUNNING stanju, tada se ono nastavlja izvršavati.
Zašto se provjerava da li je RUNNING, a ne RUNNABLE? Zato jer je ustanovljeno da nije RUNNABLE u zadnjoj iteraciji petlje.

Ako nakon svega ovoga i dalje nije pokrenuto neko okruženje, tada se poziva funkcije `sched_halt`.
Tok programa se ne vraća iz funkcija `env_run` i `sched_halt`.

Dalje, potrebno je dodati dispatch za sistemski poziv `sys_yield` u funkciji `syscall` u fajlu [`syscall.c`](../kern/syscall.c):
``` c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
  switch (syscallno)
  {
            ...
  case SYS_yield:
    sys_yield();
    // should not return
    panic("syscall: sys_yield returned");
            ...
  }
}
```

I na kraju potrebno je u funkciji `i386_init`, u fajlu [`init.c`](../kern/init.c) napraviti 3 okruženja `user_yield`:
``` c
void i386_init(void)
{
                ...
  ENV_CREATE(user_yield, ENV_TYPE_USER);
  ENV_CREATE(user_yield, ENV_TYPE_USER);
  ENV_CREATE(user_yield, ENV_TYPE_USER);
                ...
  sched_yield();
}
```


## Question 3
#### In your implementation of `env_run()` you should have called `lcr3()`. Before and after the call to `lcr3()`, your code makes references (at least it should) to the variable `e`, the argument to `env_run`. Upon loading the `%cr3` register, the addressing context used by the MMU is instantly changed. But a virtual address (namely `e`) has meaning relative to a given address context--the address context specifies the physical address to which the virtual address maps. Why can the pointer `e` be dereferenced both before and after the addressing switch? 
U funkciji `env_run` iz [`env.c`](../kern/env.c) se zaista koristi `e` prije i posle učitavanja adresnog prostora okruženja:
``` c
void env_run(struct Env* e)
{
              ...
  curenv = e;
  curenv->env_status = ENV_RUNNING;
              ...
  lcr3(PADDR(e->env_pgdir));
  env_pop_tf(&e->env_tf);
}
```

Ovo je uredu i radi zato jer se sva okruženja nalaze u nizu `envs`,
koji je globalna varijabla definisana u [`env.c`](../kern/env.c):
``` c
struct Env* envs = NULL; // All environments
```

Dakle `envs`, pa time i sva okruženja, se nalaze u `.data` sekciji kernela.
Time se može zaključiti da se `envs` nalazi negdje iznad `KERNBASE`.
A virtuelna memorija iznad `KERNBASE` je mapirana u svim okruženjima na isti način, kao i u kernelu.

Ovo se također može provjeriti koristeći GDB:
``` console
(gdb) print &envs
$1 = (struct Env **) 0xf0248268 <envs>
```
iz čega se vidi da se `envs` nalazi na adresi `0xf0248268`, pa je time cijeli niz mapiran u svim virtuelnim adresnim prostorima.


## Question 4
#### Whenever the kernel switches from one environment to another, it must ensure the old environment's registers are saved so they can be restored properly later. Why? Where does this happen?
Ako kernel ne bi sačuvao registre od okruženja koje se izvršavalo, tada bi pri povratku u to okruženje procesor bio u totalno drugačijem stanju.
Npr. ako procesor spremi brojeve `2` i `3` u neka dva registra sa namjerom da ih sabere.
U tom trekutku se desi timer interrupt i kernel pokrene neko drugo okruženje, pri čemu ne spremi stanje registara.
Ponovnim pokretanjem prvog okruženja u registrima su neke druge vrijednosti, npr. `523` i `-32`.
Ovo se jasno ne bi smjelo desiti.

Znači, kernel sprema registre okruženja kako bi okruženje moglo se nastaviti izvršavati tačno iz onog stanja u kojem je prekinuto.

Ovo spremanje registara se radi u funkciji `trap` u fajlu [`trap.c`](../kern/trap.c):
``` c
void trap(struct Trapframe* tf)
{
                ...
  if ((tf->tf_cs & 3) == 3)
  {
                ...
    curenv->env_tf = *tf; // <<<<<<<<<<
  }
                ...
}
```

`tf` predstavlja trapframe koji se nalazi na stacku, odnosno stanje procesora prekinutog okruženja u trenutku prekida.
`curenv` predstavlja pointer na element iz niza `envs` koji predstavlja to okruženje.
Linijom koda koja je označena iznad se stanje procesora iz `tf` pamti kao stanje procesora za to okruženje.
Sljedeći puta kada se to okruženje bude pokretalo, kernel će ga naći u nizu `envs`, pročitati njegov trap frame (`env_tf`) 
i učitati ga u procesor čime se to okruženje nastavlja izvršavati tačno od onog stanja u kojem je bilo kada je prekinuto.


# System Calls for Environment Creation

# Exercise 7
Implementacije sistemskih poziva se nalaze u [`syscall.c`](../kern/syscall.c).

### `sys_exofork`
``` c
static envid_t
sys_exofork(void)
{
  struct Env* newenv;
  int alloc_ret = env_alloc(&newenv, curenv->env_id); // get new enviroment

  // check if enviroment allocation failed
  if (alloc_ret)
    return alloc_ret;

  newenv->env_status = ENV_NOT_RUNNABLE;
  newenv->env_tf = curenv->env_tf;    // copy registers
  newenv->env_tf.tf_regs.reg_eax = 0; // set return value of child to 0

  return newenv->env_id;
}
```

### `sys_env_set_status`
``` c
static int
sys_env_set_status(envid_t envid, int status)
{
  struct Env* e;

  // check if enviroment id is valid and permissions
  if (envid2env(envid, &e, 1))
    return -E_BAD_ENV;

  // check if status argument is valid
  if (status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE)
    return -E_INVAL;

  e->env_status = status;

  return 0;
}
```

### `sys_page_alloc`
``` c
static int
sys_page_alloc(envid_t envid, void* va, int perm)
{
  struct Env* e;
  struct PageInfo* newpage;

  // check if enviroment id is valid and permissions
  if (envid2env(envid, &e, 1))
    return -E_BAD_ENV;

  // check if va is in user space and if it's page aligned
  if ((uintptr_t)va >= UTOP || (uint32_t)va % PGSIZE)
    return -E_INVAL;

  // check if wanted permissions are allowed
  if (perm & ~PTE_SYSCALL)
    return -E_INVAL;

  // allocate a new page and check if it's successful
  if (!(newpage = page_alloc(ALLOC_ZERO)))
    return -E_NO_MEM;

  // try to insert the new page in the given enviroment's address space
  if (page_insert(e->env_pgdir, newpage, va, perm | PTE_U)) // PTE_P always set by page_insert
  {
    // if insertion fails free the page
    page_free(newpage);
    return -E_NO_MEM;
  }

  return 0;
}
```

### `sys_page_map`
``` c
static int
sys_page_map(envid_t srcenvid, void* srcva,
  envid_t dstenvid, void* dstva, int perm)
{
  struct Env* e_src;
  struct Env* e_dst;
  struct PageInfo* page;
  pte_t* pte;

  // check if source enviroment id is valid and permissions
  if (envid2env(srcenvid, &e_src, 1))
    return -E_BAD_ENV;

  // check if destination enviroment id is valid and permissions
  if (envid2env(dstenvid, &e_dst, 1))
    return -E_BAD_ENV;

  // check if source va is in user space and if it's page aligned
  if ((uintptr_t)srcva >= UTOP || (uint32_t)srcva % PGSIZE)
    return -E_INVAL;

  // check if destination va is in user space and if it's page aligned
  if ((uintptr_t)dstva >= UTOP || (uint32_t)dstva % PGSIZE)
    return -E_INVAL;

  // get page and it's pte
  if (!(page = page_lookup(e_src->env_pgdir, srcva, &pte)))
    return -E_INVAL;

  // check if wanted permissions are allowed
  if (perm & ~PTE_SYSCALL)
    return -E_INVAL;

  // check if page is read only but perm has PTE_W
  if (perm & PTE_W && !(*pte & PTE_W))
    return -E_INVAL;

  // insert the page in the destination enviroment address space
  if (page_insert(e_dst->env_pgdir, page, dstva, perm))
    return -E_NO_MEM;

  return 0;
}
```

### `sys_page_unmap`
``` c
static int
sys_page_unmap(envid_t envid, void* va)
{
  struct Env* e;

  // check if enviroment id is valid and permissions
  if (envid2env(envid, &e, 1))
    return -E_BAD_ENV;

  // check if va is in user space and if it's page aligned
  if ((uintptr_t)va >= UTOP || (uint32_t)va % PGSIZE)
    return -E_INVAL;

  // remove the page mapped at va from the enviroment's address space
  page_remove(e->env_pgdir, va);

  return 0;
}
```

### Dispatch

Također je potrebno dodati dispatch za nove sistemske pozive.
``` c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
  switch (syscallno)
  {
            ...
  case SYS_exofork:
    return sys_exofork();
  case SYS_env_set_status:
    return sys_env_set_status(a1, a2);
  case SYS_page_alloc:
    return sys_page_alloc(a1, (void*)a2, a3);
  case SYS_page_map:
    return sys_page_map(a1, (void*)a2, a3, (void*)a4, a5);
  case SYS_page_unmap:
    return sys_page_unmap(a1, (void*)a2);
            ...
  }
}
```

