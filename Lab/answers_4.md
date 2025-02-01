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

    // Garbage collect if current environment is a zombie
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


## Challenge 1
Implementirana su 4 nova lock-a:
- `page_allocator_lock`
- `console_driver_lock`
- `scheduler_lock`
- `ipc_lock`


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


## Challenge 2
Dodani prioriteti za okruženja u [`env.h`](../inc/env.h).
Implementiran fixed priority scheduling u [`sched.c`](../kern/sched.c).
Implementiran sistemski poziv [`sys_env_set_priority`](../kern/syscall.c).
Dodan novi program [`fpschedtest`](../user/fpschedtest.c) za testiranje novog scheduling-a.


# System Calls for Environment Creation

## Exercise 7
Implementacije sistemskih poziva se nalaze u [`syscall.c`](../kern/syscall.c).

### `sys_exofork`
``` c
static envid_t
sys_exofork(void)
{
  struct Env* newenv;
  int alloc_ret = env_alloc(&newenv, curenv->env_id); // get new environment

  // check if environment allocation failed
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

  // check if environment id is valid and permissions
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

  // check if environment id is valid and permissions
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

  // try to insert the new page in the given environment's address space
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

  // check if source environment id is valid and permissions
  if (envid2env(srcenvid, &e_src, 1))
    return -E_BAD_ENV;

  // check if destination environment id is valid and permissions
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

  // insert the page in the destination environment address space
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

  // check if environment id is valid and permissions
  if (envid2env(envid, &e, 1))
    return -E_BAD_ENV;

  // check if va is in user space and if it's page aligned
  if ((uintptr_t)va >= UTOP || (uint32_t)va % PGSIZE)
    return -E_INVAL;

  // remove the page mapped at va from the environment's address space
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



<div align='center'><h1 align='center'>Part B: Copy-on-Write Fork</h1></div>

# User-level page fault handling

# Setting the Page Fault Handler

## Exercise 8
Implementiran je novi sistemski poziv `sys_env_set_pgfault_upcall` u fajlu [`syscall.c`](../kern/syscall.c) 
kojim korisničko okruženje dadne kernelu funkciju koja će se koristiti pri tretiranju user level page fault-a.
Pointer na tu funkciju se zapisuje u polju `env_pgfault_upcall` datog okruženja.
Prije nego što se postavi pomenuto polje u `Env` strukturi za dato okruženje,
potrebno je ispitati validnost datog `envid` i da li okruženje uopće ima odgovarajuće permisije.
``` c
static int
sys_env_set_pgfault_upcall(envid_t envid, void* func)
{
  struct Env* e;

  // check if environment id is valid and permissions
  if (envid2env(envid, &e, 1))
    return -E_BAD_ENV;

  // set page fault upcall for given environment
  e->env_pgfault_upcall = func;

  return 0;
}
```

Na kraju dodan je dispatch za novo-implementirani sistemski poziv u funkciji `syscall` u fajlu [`syscall.c`](../kern/syscall.c) .
``` c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
  switch (syscallno)
  {
                ...
  case SYS_env_set_pgfault_upcall:
    return sys_env_set_pgfault_upcall(a1, (void*)a2);
                ...
  }
}
```


# Invoking the User Page Fault Handler

## Exercise 9
Potrabno je implementirati dio funkcije `page_fault_handler` za slučaj kada se page fault tretira u user modu.
Ako je trenutno okruženje postavilo upcall funkciju za page fault (`env_pgfault_upcall`),
to znači da će se page fault tretirati u user modu pomoću funkcije na koji pokazuje `env_pgfault_upcall`.
U tom slučaju potrebno je provjeriti gdje se page fault desio, provjeriti permisije, 
napraviti user trap frame i ponovo pokrenuti oruženje tako da tretira svoj page fault.

Slijedi implementacija pomenutom dijela funkcije `page_fault_handler` iz fajl [`trap.c`](../kern/trap.c):
``` c
void page_fault_handler(struct Trapframe* tf)
{
  uint32_t fault_va;
  fault_va = rcr2();
                            ...
  if (curenv->env_pgfault_upcall)
  {
    struct UTrapframe* utf; // user trap frame

    // check where the page fault happened
    if (tf->tf_esp < UXSTACKTOP && tf->tf_esp >= UXSTACKTOP - PGSIZE)
    {
      // page fault happened on the user exception stack
      *((uint32_t*)(tf->tf_esp - 4)) = 0;                                     // push empty word
      utf = (struct UTrapframe*)(tf->tf_esp - 4 - sizeof(struct UTrapframe)); // push user trap frame below last esp and empty word
    }
    else
      utf = (struct UTrapframe*)(UXSTACKTOP - sizeof(struct UTrapframe)); // push user trap frame at top of user exception stack

    // check memory permissions
    user_mem_assert(curenv, utf, sizeof(struct UTrapframe), PTE_U | PTE_W);

    // set up user trap frame
    utf->utf_fault_va = fault_va;
    utf->utf_err = tf->tf_err;
    utf->utf_regs = tf->tf_regs;
    utf->utf_eip = tf->tf_eip;
    utf->utf_eflags = tf->tf_eflags;
    utf->utf_esp = tf->tf_esp;

    // set up esp and eip for user environment when it starts running again
    // so it can handle the page fault
    tf->tf_esp = (uintptr_t)utf;
    tf->tf_eip = (uintptr_t)curenv->env_pgfault_upcall;

    // run user environment from it's page fault upcall function
    env_run(curenv);
  }
                            ...
}
```

Varijabla `utf` je pointer na user trap frame.
User trap frame je struktura (`struct UTrapframe`) koja sadrži stanje procesora 
u trenutku kada se desio page fault u user modu.
Nju koristi page fault handler (`env_pgfault_upcall`) pri tretiranju page faulta.

User trap frame treba da se napravi na različitim mjestima u različitim slučajevima, i to
za slučaj da se page fault desio dok je okruženje koristilo:
- user stack, tada se user trap frame pravi na vrhu user exception stack-a.
- user *exception* stack, tada se user trap frame pravi na dnu korištenog user exception stacka (gdje pokazuje user stack pointer), 
  pri čemu je potrebno ostaviti jedan "prazan" word iznad user trap frame-a (vrijednost `0` od 4B)

Ako je stack pointer od odruženja (`tf_esp`) bio u opsegu `[UXSTACKTOP - PGSIZE, UXSTACKTOP)` 
to znači da se page fault desio dok je okruženje koristilo user exception stack.

Potrebno je također provjeriti da li okruženje ima permisije da pristupa user trap frame-u koji će kernel napraviti,
što se može uraditi pomoći funkcije `user_mem_assert` koja je implementirana u fajlu [`pmap.c`](../kern/pmap.c) u prethodnom lab-u.

Dalje, user trap frame se popunjava vrijednostima iz trap frame-a (`tf`), 
pri čemu se vrijednost za `utf_fault_va` čita iz registra `%cr2` 
u kojem je zapisana adresa koja je prouzrokovala page fault.

Na kraju se stack pointer okruženja (`tf_esp`) postavlja na početak user trap frame-a (user exception stack),
instruction pointer okruženja (`tf_eip`) se postavlja na adresu funkcije koja će tretirati page fault u user modu (`env_pgfault_upcall`) i 
okruženje se ponovo pokreće, čime ono počinje tretirati page fault.

#### What happens if the user environment runs out of space on the exception stack?
U slučaju da okruženje ispuni cijeli user exception stack i pokuša pushati nešto izvan page-a alociranog za exception stack 
desit će se page fault. Tada se cijeli prethnodno objašnjen proces ponavlja pri čemu se pravi novi user trap frame.
Taj user trap frame će počinjati na adresi koja je izvan user exception stacka (`utf` će biti ispod `UXSTACKTOP - PGSIZE`).
U tom slučaju će pasti `user_mem_assert`. Zašto i šta se desi tada? Pogledajmo implementaciju funkcije `user_mem_assert` iz fajla [`pmap.c`](../kern/pmap.c):
``` c
void user_mem_assert(struct Env* env, const void* va, size_t len, int perm)
{
  if (user_mem_check(env, va, len, perm | PTE_U) < 0)
  {
    cprintf("[%08x] user_mem_check assertion failure for "
            "va %08x\n",
      env->env_id, user_mem_check_addr);
    env_destroy(env); // may not return
  }
}
```

Ako funkcija `user_mem_check` **ne** vrati `NULL`, tada se okruženje uništava.
Pogledajmo kada će `user_mem_check` vratiti `NULL`, odnosno kada neće, u fajlu [`pmap.c`](../kern/pmap.c):
``` c
int user_mem_check(struct Env* env, const void* va, size_t len, int perm)
{
  uintptr_t _va = (uintptr_t)va; // just changed type to avoid casts for readability
  uintptr_t end_va = _va + len;

  // check if user is trying to access out of user virtual memory
  if (end_va >= ULIM)
  {
    user_mem_check_addr = _va;
    return -E_FAULT; // <<<<<<<<<<
  }

  for (uintptr_t addr = ROUNDDOWN(_va, PGSIZE); addr < end_va; addr += PGSIZE)
  {
    pte_t* pte = pgdir_walk(env->env_pgdir, (void*)addr, 0);

    if (!pte || (*pte & perm) != perm || !(*pte & PTE_P))
    {
      user_mem_check_addr = addr > _va ? addr : _va; // set to larger
      return -E_FAULT; // <<<<<<<<<<<<<<<<<<<<
    }
  }

  return 0;
}
```
Dakle, `user_mem_check` **ne** vraća `NULL` u slučajevima:
- najviša adresa dijela memorije koji se provjerava prelazi `ULIM` (ne bi se trebalo desiti pri korištenju user exception stacka)
- neka adresa iz dijela memorije koji se provjerava nema dovoljne permisije
- neka adresa iz dijela memorije koji se provjerava nije mapirana (`pte` je `NULL` ili `PTE_P` u `pte` nije setovan)

Zadnji slučaj je najvjerovatniji da se desi, i upravo ovo je razlog uništavanja okruženja za slučaj da se cijeli user exception stack popuni.

**TL;DR: okruženje se uništava.**



# User-mode Page Fault Entrypoint


## Exercise 10
Za implementaciju `_pgfault_upcall` korisno je posmatrati user trap frame:
```
                    <-- UXSTACKTOP
trap-time esp       (2)
trap-time eflags    (5)
trap-time eip       (3)
trap-time eax       start of struct PushRegs
trap-time ecx
trap-time edx
trap-time ebx
trap-time oesp
trap-time ebp
trap-time esi
trap-time edi       (4) end of struct PushRegs
tf_err (error code)
fault_va            (1) <-- %esp when handler is run
```

Oznake `(1), (2), (3), (4), (5)` će biti referencirane kasnije (u objašnjenju implementacije).

Na osnovu user trap frame-a implementirana ja asembler funkcija `_pgfault_upcall` u fajlu [`pfentry.S`](../lib/pfentry.S).
Dio ove funkcije je već implementirao MIT. Prethodno implementirani dio i novo-implementirani dio su razdvojeni.

``` asm
.text
.globl _pgfault_upcall
_pgfault_upcall:
    // Call the C page fault handler.
    pushl %esp           // function argument: pointer to UTF
    movl _pgfault_handler, %eax
    call *%eax
    addl $4, %esp        // pop function argument

    // ^^^^^^^^^^^^^^^^^^^^^^^^ prethodno implementirano ^^^^^^^^^^^^^^^^^^^^^^^^ //
    ////////////////////////////////////////////////////////////////////////////////
    // vvvvvvvvvvvvvvvvvvvvvvvvvvv novo-implementirano vvvvvvvvvvvvvvvvvvvvvvvvvv //

    subl $4, 48(%esp)    // increment trap-time esp by 4
    movl 48(%esp), %eax  // move incremented trap-time esp into %eax
    movl 40(%esp), %ecx  // move value of trap-time eip into %ecx
    movl %ecx, (%eax)    // move value of trap time eip to bottom of trap-time stack

    // Restore the trap-time registers.
    addl $8, %esp   // skip fault_va and error code
    popal           // load general-purpose registers from stack into cpu

    // Restore eflags from the stack.
    addl $4, %esp   // skip %eip
    popfl           // load eflags from stack into cpu

    // Switch back to the adjusted trap-time stack.
    popl %esp       // load trap-time %esp from stack into cpu

    // Return to re-execute the instruction that faulted.
    ret             // continue execution from trap-time %eip
```

U prethodno implementiranom dijelu se pripremi arguument i poziva page fault handler (`_pgfault_handler`)
koji tretira page fault, nakon čega se argument pop-a sa stacka. Nakon ovoga stack ostaje u istom stanju kao i prethodno, 
tj. iznad `%esp` se nalazi user trap frame koji je kernel pripremio u funkciji `page_fault_handler`.

U novo-implementiranom dijelu, page fault je već tretiran i cilj je prebaciti procesor sa user exception stacka na user stack 
i nastaviti izvršavati kod sa mjesta gdje se desio page fault kao da se ništa nije desilo. 
Da bi se stvorila ta iluzija potrebno je vratiti stanja svih registara na vrijednosti kakve su bile prije page faulta.

Problemi su sljedeći:
- ako se promijeni stack ne mogu se koristiti vrijednosti pohranjene na "prošlom" stacku
- ako se vrati stanje registara opšte namjene njihove vrijednosti se više ne smiju mijenjati
- ako se vrati stanje flags registra (`%eflags`) ne smiju se izvršavati instrukcije koje bi promijenile neki flag u njemu
- cijelo stanje procesora se mora vratiti prije promjene instruction pointer-a (`%eip`), 
  jer se time nastavlja izvršavati user mode funkcija koja ne zna ništa o page fault-u

Uzimajući sve ovo u obzir može se zaključiti par stvari:
- stanje registra `%eip` se mora vratiti zadnje
- stanje registra `%esp` se mora vratiti tik prije stanja `%eip`
- stanje registra `%eflags` se mora vratiti što kasnije moguće
- stanje registra `%esp` se mora vratiti na način da se ne promijeni `%eflags`
- nakon što se vrate stanja registara opšte namjene mora se isključivo koristiti stack za pohranu podataka

U jednom potezu se može vratiti vrijednost `%eip` pomoću instrukcije `ret`, što znači da će instrukcija `ret` biti zadnja instrukcija u ovoj funkciji.
Instrukcija `ret` pop-a vrijednost sa stack-a u `%eip`.
Međutim, ta instrukcija se mora izvršiti na user stacku, jer je prije promjene `%eip` potrebno promijeniti stack sa user exception stacka na user stack.
Dakle, vrijednost za `%eip` se mora pohraniti na user stacku nakon čega će se izvršiti instrukcija `ret` i nastavit se izvršenje okruženja tamo gdje je stalo.
Da bi se pohranila vrijednost na user stacku potreban user pointer na user stack.
Također je potrebno napraviti prostora na user stacku inkrementiranjem njegovog `%esp`.
Vrijednost za `%eip` je velika 4B, pa je potrebno napraviti toliko prostora.

Konačno dolazimo do implementacije.

Na početku se `%esp` nalazi na `(1)`.
`%esp` user stacka se nalazi na `(2)`.
Razlika između ovih vrijednosti je `12 * 4B`, odnosno `48B`.

Pomoću sljedećih instrukcija se pomijera user stack pointer i njegova nova vrijednost sprema u `%eax`:
```asm
    subl $4, 48(%esp)    // increment trap-time esp by 4
    movl 48(%esp), %eax  // move incremented trap-time esp into %eax
```

Vrijednost koju treba imati `%eip` kada se nastavi izvršavanje okruženja na mjestu gdje je stalo je na `(3)`.
Razlika između `%esp` (`(1)`) i `(3)` je `10 * 4B`, odnosno `40B`.

Pomoću sljedećih instrukcija se vrijednost za user `%eip` smiješta na prethodno napravljen prostor (`4B`) na dnu user stacka (prethodno pohranjeno u `%eax`):
``` asm
    movl 40(%esp), %ecx  // move value of trap-time eip into %ecx
    movl %ecx, (%eax)    // move value of trap time eip to bottom of trap-time stack
```

Dalje, potrebno je vratiti vrijednosti registara opšte namjene.
Oni se nalaze na stacku počevši od `(4)`.
Korisnički program ne zanima adresa na kojoj se desio page fault niti error code, pa se mogu ignorisati i "preskočiti".
Razlika između `(4)` i `(1)` (trenutna vrijednost `%esp`) je `2 * 4B`, odnosno `8B`, pa je za toliko potrebno povećati `%esp`.
Nakon `addl` instrukcije `%esp` se nalazi na `(4)`, nakon čega se pomoću instrukcije `popal` 
vraćaju vrijednosti registara opšte namjene u procesor i `%esp` dolazi na `(3)`.
Od tog trenutka se ne smiju više koristiti registri opšte namjene jer bi im se promijenile vrijednosti.

``` asm
    addl $8, %esp   // skip fault_va and error code
    popal           // load general-purpose registers from stack into cpu
```

Vrijednost za `%eip`, koja se nalazi na `(3)` je već pohranjena na user stacku, pa se može ignorisati i "preskočiti", čime `%esp` dolazi na `(5)`.

``` asm
    addl $4, %esp   // skip %eip
```

Preostalo je još vratiti vrijednosti za `%eflags`, `%esp` i `%eip`.
Vrijednost za `%eflags` se nalazi na `(5)`, gdje i pokazuje `%esp`, 
pa se direktno vraća sa stacka pomoću instrukcije `popfl`, čime `%esp` dolazi na `(2)`.

``` asm
    popfl           // load eflags from stack into cpu
```

Na isti način se vrši promjena stacka, odnosno vraća se vrijednost za `%esp`.
`%esp` je na `(2)`, pa se nakon `popl %esp` ta vrijednost učitaje u `%esp`, čime se prelazi na user stack.

``` asm
    popl %esp       // load trap-time %esp from stack into cpu
```

Sada se nalazimo na user stacku, na mjestu gdje je prethodno pohranjena vrijednost za `%eip`.
Instrukcijom `ret` se na učitava u procesor, čime se nastavlja izvršavanje okruženja na mjestu gdje se desio page fault.


## Exercise 11
Funkcija `set_pgfault_handler` je implementirana u fajlu [`pgfault.c`](../lib/pgfault.c):
``` c
void set_pgfault_handler(void (*handler)(struct UTrapframe* utf))
{
  if (_pgfault_handler == 0)
  {
    int err;

    // allocate new page using syscall
    err = sys_page_alloc(thisenv->env_id, (void*)UXSTACKTOP - PGSIZE, PTE_W); // PTE_P set by page_insert; PTW_U set by sys_page_alloc

    // panic and print error if there is one
    if (err)
      panic("sys_pgfault_handler - sys_page_alloc: %e", err);

    // set page upcall function using syscall
    err = sys_env_set_pgfault_upcall(thisenv->env_id, _pgfault_upcall);

    // panic and print error if there is one
    if (err)
      panic("sys_pgfault_handler - sys_env_set_pgfault_upcall: %e", err);
  }

  // Save handler pointer for assembly to call.
  _pgfault_handler = handler;
}
```

Ova funkcija je poprilično jednostavna.
Ukoliko page fault handler (`_pgfault_handler`) nije inicijaliziran (ima vrijednost `0`, odnosno `NULL`), tada radi sljedeće.

Ukratko, koristi sistemski poziv `sys_page_alloc` da alocira jednu stranicu za user exception stack i 
mapira je na adresu `UXSTACKTOP - PGSIZE` (dno user exception stacka) sa permisijama za pisanje.
Dalje, pomoću sistemskog poziva `sys_env_set_pgfault_upcall` postavlja page fault upcall funkciju na `_pgfault_upcall`, 
koja je prethodno implementirana u ***exercise 10***, u fajlu [`pfentry.S`](../lib/pfentry.S).
Pri povratku iz sistemskih poziva također provjerava da li se desila neka greška, i ako jest paničari.

Na kraju postavlja globalnu varijablu `_pgfault_handler` na proslijeđeni `handler`.
Varijabla `_pgfault_handler` je tipa pointer na funkciju koja prima jedan argument tipa `struct UTrapframe*`.


## Challenge 5
U ovom challenge-u je implementirana mogućnost da se sve iznimke tretiraju u user modu.


# Implementing Copy-on-Write Fork


## Exercise 12
Copy-on-write fork je implementacija forka u kojoj i parent i child 
okruženje koristi iste stranice sve dok jedno od njih ne pokuša pisati u neku stranicu.
Child okruženje samo ima mapiranje stranica od parent okruženja.
Kada parent ili child okruženje pokuša pisati u neku stranicu,
tada i parent i child dobijaju svoju kopiju te stranice.

Kopiranje stranica nije performatno, pa se na ovaj način izbjegaje
kopiranje stranica sve dok to nije apsolutno potrebno.
Sve dok oba okruženja samo čitaju podatke, podaci ostaju isti pa nema potrebe kopirati ih.


### `fork`

Funkcija `fork` u fajlu [`fork.c`](../lib/fork.c) implementira ovu metodu forkanja:
``` c
envid_t
fork(void)
{
  envid_t envid;

  // set up page fault handler
  set_pgfault_handler(pgfault);

  // create child; returns 0 to child, id of child environment to parent
  envid = sys_exofork();

  // if sys_exofork failed return the same error to fork caller
  if (envid < 0)
    return envid;

  // check if we're executing from child
  if (!envid)
  {
    // executing from child; fix thisenv
    thisenv = &envs[ENVX(sys_getenvid())];
    return envid; // returns 0; end of function for child
  }

  // executing from parent, envid is child's id

  // copy parent address space into child address space
  for (uintptr_t va = 0x0; va < USTACKTOP; va += PGSIZE)
  {
    pde_t pde = uvpd[PDX(va)];

    // check if pde is present
    if (!(pde & PTE_P))
      continue;

    pte_t pte = uvpt[PGNUM(va)];

    // if PDE and PTE are present duplicate the page
    if (pte & PTE_P)
      duppage(envid, PGNUM(va));
  }

  // set up child exception stack
  int err;

  // allocate new page for child exception stack
  err = sys_page_alloc(envid, (void*)(UXSTACKTOP - PGSIZE), PTE_W); // PTE_U and PTE_P set by sys_page_alloc

  // return error if there is one
  if (err)
    return err;

  // set up child page fault upcall
  void _pgfault_upcall(); // implemented in /lib/pfentry.S
  err = sys_env_set_pgfault_upcall(envid, _pgfault_upcall);

  // return error if there is one
  if (err)
    return err;

  // set child status to RUNNABLE
  err = sys_env_set_status(envid, ENV_RUNNABLE);

  // return error if there is one
  if (err)
    return err;

  return envid;
}
```

Pomoću sistemskog poziva `sys_exofork` se kreira child okruženja
koje ima iste registre kao i parent okruženje.
Od povratka iz ovog sistemskog poziva kod dalje izvršavaju i parent i child okruženje.
Razlika između njih je što u child okruženju vrijednost varijable `envid` (povratna vrijednost sistemskog poziva)
je `0`, a u parent okruženju je id child okruženja.

U child okruženju se mijenja njegova glovalna varijabla `thisenv` tako da stvarno pokazuje na child okruženje. 
Ovdje se završava izvršenje funkcije `fork` u child okruženju.

Parent okruženje kopira mapiranja svog virtuelnog adresnog prostora u child okruženje.
Ovo se vrši pomoću `for` petlje u kojoj se svaka stranica koja je mapirana u parent okruženju
mapira u child okruženju pomoću funkcije `duppage` koja je implementirana kasnije u ovom exercise-u.
Varijabla `uvpd` predstavlja page directory trenutnog (u ovom slučaju parent) okruženja, a `uvpt` predstavlja page table.
Indeksiranjem `uvpd` pomoću `PDX(va)` se dobija PDE od trenutnog okruženja koje se koristi za mapiranje stranice u kojoj je adresa `va`.
Indeksiranjem `uvpt` pomoću `PGNUM(va)` se dobija PTE od trenutnog okruženja koje se koristi za mapiranje stranice u kojoj je adresa `va`.
Ovo je "trik" sa mapiranjem koji JOS koristi.

Dalje se alocita (i mapira) stranica za child exception stack pomoću sistemskog poziva `sys_page_alloc`, 
postavlja page fault upcall funkcija pomoću sistemskog poziva `sys_env_set_pgfault_upcall` 
i postavlja status child okruženja u `ENV_RUNNABLE`.


### `duppage`

Funkcija `duppage` se koristi za dupliciranje stranice iz jednog okruženja u drugo i implementirana je u fajlu [`fork.c`](../lib/fork.c):
``` c
static int
duppage(envid_t child_envid, unsigned pn)
{
  int err;
  pte_t pte = uvpt[pn];
  uintptr_t va = pn * PGSIZE;
  envid_t parent_envid = sys_getenvid();
  uint32_t perm = PTE_U; // PTE_P is automatically set by sys_page_map

  // check if page is writable or copy-on-write
  if (pte & PTE_W || pte & PTE_COW)
  {
    // mark page as copy-on-write
    perm |= PTE_COW;

    // map page in child environment
    err = sys_page_map(parent_envid, (void*)va, child_envid, (void*)va, perm);

    // return error if there is one
    if (err)
      return err;

    // remap page in parent environment, now copy-on-write
    err = sys_page_map(parent_envid, (void*)va, parent_envid, (void*)va, perm);
  }
  else
    // map page in child environment
    err = sys_page_map(parent_envid, (void*)va, child_envid, (void*)va, perm);

  // return error if there is one
  if (err)
    return err;

  return 0;
}
```

U slučaju da je stranica koja se mapira writable ili označena kao copy-on-write,
u tom slučaju se ta stranica mapira i u child okruženju kao copy-on-write
pomoću sistemskog poziva `sys_page_map`.
Ista stranica se također remapira i u parent okruženju.
U suprotnom se samo mapira u child okruženju.


### `pgfault`

Funkcija `pgfault` se koristi za tretiranje page faulta i implementirana je u fajlu [`fork.c`](../lib/fork.c):
``` c
static void
pgfault(struct UTrapframe* utf)
{
  void* addr = (void*)utf->utf_fault_va;
  uint32_t err = utf->utf_err;
  int r;

  pte_t pte = uvpt[PGNUM(addr)];

  if (!(pte & PTE_COW && err & FEC_WR))
    panic("pgfault: not a write to a copy-on-write page");

  envid_t envid = sys_getenvid();

  // allocate new page and map it to PFTEMP
  r = sys_page_alloc(envid, PFTEMP, PTE_W); // PTE_U and PTE_P set by sys_page_alloc

  // return error if there is one
  if (r) panic("pgfault: from sys_page_alloc -> %e", r);

  // copy data from old page to new page
  memcpy(PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);

  // map the new page at the old page address
  r = sys_page_map(envid, PFTEMP, envid, ROUNDDOWN(addr, PGSIZE), PTE_U | PTE_W);

  // return error if there is one
  if (r) panic("pgfault: from sys_page_map -> %e", r);

  // unmap temp page
  r = sys_page_unmap(envid, PFTEMP);

  // return error if there is one
  if (r) panic("pgfault: from sys_page_unmap -> %e", r);
}
```

U slučaju da se adresa koja je izazvala page fault ne nalazi u stranici 
koja je označena kao copy-on-write ili ako page fault nije izazvan pokušajem pisanja,
u tom slučaju okruženje paničari.

Dalje, alocira se nova stranica koja se privremeno mapira na `PFTEMP`.
Stranica u kojoj je adresa koja je izazvala page fault se kopira u novo-alociranu stranicu pomoću funkcije `memcpy`.
Dalje, ta novo-alocirana stranica se mapira na adresu stranice koja je izazvala page fault, a stranica mapirana na `PFTEMP` se demapira.


## Challenge 6
`sfork` je implementiran u fajlu [`fork.c`](../lib/fork.c).
Promijenjena je funkcionalnost `thisenv` tako da u svakom okruženju pokazuje na to okruženje.
Pored ovoga, također je napisan program [`sforktest`](../user/sforktest.c) koji provjerava funkcionalnost `sfork`-a.



<div align='center'><h1 align='center'>Part C: Preemptive Multitasking and Inter-Process communication (IPC)</h1></div>

# Clock Interrupts and Preemption

## Exercise 13
Handleri za IRQ se definišu u [`trapentry.S`](../kern/trapentry.S) na isti način kao i handleri za iznimke, pomoću makroa `TRAPHANDLER` i `TRAPHANDLER_NOEC`.
Budući da ni jedan IRQ handler ne pusha error code na stack, za keiranje IRQ handlera koristi se isključivo `TRAPHANDLER_NOEC`.
Handleri za IRQ su definisani nakon handlera za iznimke, nakon labela `_trap_handlers`, kako bi se pomoću istog moglo im pristupati.

U [`trapentry.S`](../kern/trapentry.S) je definisano prvih 16 IRQ handlera, kako je navedeno u exercise-u:
``` asm
.data
.global _trap_handlers
_trap_handlers:
.text
TRAPHANDLER_NOEC(th_divide,  T_DIVIDE)
                  ...
TRAPHANDLER_NOEC(th_simderr, T_SIMDERR)
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ //
//                  OLD                  //
///////////////////////////////////////////
//                  NEW                  //
// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv //
TRAPHANDLER_NOEC(th_irq_0, IRQ_OFFSET + 0)
TRAPHANDLER_NOEC(th_irq_1, IRQ_OFFSET + 1)
TRAPHANDLER_NOEC(th_irq_2, IRQ_OFFSET + 2)
TRAPHANDLER_NOEC(th_irq_3, IRQ_OFFSET + 3)
TRAPHANDLER_NOEC(th_irq_4, IRQ_OFFSET + 4)
TRAPHANDLER_NOEC(th_irq_5, IRQ_OFFSET + 5)
TRAPHANDLER_NOEC(th_irq_6, IRQ_OFFSET + 6)
TRAPHANDLER_NOEC(th_irq_7, IRQ_OFFSET + 7)
TRAPHANDLER_NOEC(th_irq_8, IRQ_OFFSET + 8)
TRAPHANDLER_NOEC(th_irq_9, IRQ_OFFSET + 9)
TRAPHANDLER_NOEC(th_irq_10, IRQ_OFFSET + 10)
TRAPHANDLER_NOEC(th_irq_11, IRQ_OFFSET + 11)
TRAPHANDLER_NOEC(th_irq_12, IRQ_OFFSET + 12)
TRAPHANDLER_NOEC(th_irq_13, IRQ_OFFSET + 13)
TRAPHANDLER_NOEC(th_irq_14, IRQ_OFFSET + 14)
TRAPHANDLER_NOEC(th_irq_15, IRQ_OFFSET + 15)
```

IDT entries za IRQ počinju od indeksa `IRQ_OFFSET`.
To znači da se za IRQ 0 koristi IDT entry na indeksu `IRQ_OFFSET`.
Generalnije, IDT entry za IRQ `n` se nalazi na indeksu `IRQ_OFFSET + n`.

Budući da su IRQ handler idefinisani nakon `T_SIMDERR` handlera,
to znači da se prvom IRQ handleru (`th_irq_0`) može pristupati sa 
`_trap_handlers[T_SIMDERR + 1]`, drugom sa `_trap_handlers[T_SIMDERR + 2]`, itd.
Prateći ovu logiku, može se definisani `IRQ_TH_OFFSET` kao `T_SIMDERR + 1`,
pa će handler za `n`-ti IRQ biti na indeksu `IRQ_TH_OFFSET + n` niza `_trap_handlers`.

Također je tip u deklaraciji `_trap_handlers` promijenjen na niz pointera na funkcije koje 
ne uzimaju ništa i ne vraćaju ništa kako bi bolje opisao trap handlere.

Ispod je inicijalizacija IDT entry-a za prvih 16 IRQ u funkciji `trap_init`, u fajlu [`trap.c`](../kern/trap.c):
``` c
void trap_init(void)
{
                ...
  extern void (*_trap_handlers[])(void);
                ...
  int IRQ_TH_OFFSET = T_SIMDERR + 1;
  for (int t = 0; t <= 15; ++t)
    SETGATE(idt[IRQ_OFFSET + t], 0, GD_KT, _trap_handlers[IRQ_TH_OFFSET + t], 0);
                ...
}
```

Dalje, omogućeni su prekidi za svako novo okruženje koje se alocira tako što se interrupt flag setuje (postavi na 1).

Interrupt flag je bit 9 (počevši od 0; `0x0200`) u registru `eflags`.
Ovaj bit je definisan u [`mmu.h`](../inc/mmu.h) kao `FL_IF`.
Registar `eflags` novo-alociranog okruženja `e` se nalazi u njegovom trap frame-u, i to u polju `tf_eflags`.

Koristeći bitwise or operator (`|`) može se setovati interrupt flag u novo-alociranom okruženju
u funkciji `env_alloc`, u fajlu [`env.c`](../kern/env.c), na sljedeći način:
``` c
int env_alloc(struct Env** newenv_store, envid_t parent_id)
{
              ...
  e->env_tf.tf_eflags |= FL_IF;
              ...
}
```

Također je odkomentarisana instrukcija `sti` u inline assembleru u funkciji `sched_halt` u fajlu [`sched.c`](../kern/sched.c):
``` c
void sched_halt(void)
{
            ...
  asm volatile(
    "movl $0, %%ebp\n"
    "movl %0, %%esp\n"
    "pushl $0\n"
    "pushl $0\n"
    "sti\n" // <<<<<<<<<<<<<<<<<<<<
    "1:\n"
    "hlt\n"
    "jmp 1b\n"
    : : "a"(thiscpu->cpu_ts.ts_esp0));
}
```


## Exercise 14
U određenim intervalima LAPIC dobija prekide od timer-a.
Vektor prekida za timer je `IRQ_TIMER`, konstanta definisana u [`trap.h`](../inc/trap.h).
Svaki IRQ vektor prekida je offsetan za `IRQ_OFFSET`.
Dakle, ako je u trap frame-u prekinutog okruženja u polju `tf_trapno` vrijednost `IRQ_OFFSET + IRQ_TIMER`,
to znači da se desio prekid od timera i potrebno je otići u scheduler.

Ispod je implementacija dispatch-a za timer interrupt u fajlu [`trap.c`](../kern/trap.c):
``` c
static void
trap_dispatch(struct Trapframe* tf)
{
                    ...
  if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER)
  {
    lapic_eoi();
    sched_yield();
    panic("trap_dispatch: sched_yield returned");
  }
                    ...
}
```

Prije ulazka u scheduler bitno je signalizirati LAPIC-u da je prekid tretiran i da je procesor spreman da tretira novi prekid.
Ovo je bitno uraditi prije poziva `sched_yield` jer se neće desiti povratak iz iste.
Ako se desi povratak iz `sched_yield`, nešto nije uredu pa u tom slučaju će kernel da paničari.


# Inter-Process communication (IPC)

## Exercise 15
Okruženja koriste IPC putem sistemskih poziva `sys_ipc_recv` (za primanje) i `sys_ipc_try_send` (za slanje),
koji su implementirani u [`syscall.c`](../kern/syscall.c).
Ove sistemske pozive indirektno pozivaju kroz funkcije `ipc_recv` (za primanje) i `ipc_send` (za slanje),
koje su implementirane u [`ipc.c`](../lib/ipc.c).

### `sys_ipc_recv`
Pozivom ovo sistemskog poziva okruženje govori da je spremno primiti poruku od nekog drugog okruženja i ide u stanje čekanja (`ENV_NOT_RUNNABLE`).
Okruženje se "probudi" (pređe u stanje `ENV_RUNNABLE`) kada konačno dobije poruku.
Okruženje koje šalje poruku također može mapirati stranicu iz svog adresnog prostora na adresu `dstva` okruženja koje prima poruku.
Na ovaj način od tog trenutka ta dva okruženja dijele tu stranicu.

Implementacija ovog sistemskog poziva:
``` c
static int
sys_ipc_recv(void* dstva)
{
  if ((uintptr_t)dstva < UTOP && (uintptr_t)dstva % PGSIZE)
    return -E_INVAL;

  curenv->env_ipc_recving = true;
  curenv->env_ipc_dstva = dstva; // validity is checked by sender
  curenv->env_status = ENV_NOT_RUNNABLE;

  return 0;
}
```

Ukoliko `dstva` nije u user dijelu memorije (ispod `UTOP`) i okruženje koje šalje poruku 
pokuša mapirati tu stranicu u svoj adresni prosro desit će se page fault zbog nedovoljnih privilegija.
Kako se to ne bi desilo, vrijednost `dstva` će se provjeravati u drugim funkcijama koje su implementirane u ovom exercise-u.


### `sys_ipc_try_send`
Pozivom ovog sistemskog poziva okruženje šalje poruku nekom drugom okruženju i eventualno mapira stranicu 
iz svog adresnog prostora sa adrese `srcva` u adresni prostor okruženja koje prima stranicu, 
na adresu zapisanu u polje `env_ipc_dstva` istog.

Nakon izvršenja ovog sistemskog poziva okruženje koje prima poruku će:
- biti označeno da ne želi primati poruke
- poruku dobiti u polje `env_ipc_value` svojeg `struct Env` iz niza `envs`
- biti "probuđeno", odnosno prebačeno u `ENV_RUNNABLE` stanje

Ako se izvrši mapiranje stranice, okruženje koje prima poruku će dodatno:
- imati mapiranu stranicu iz okruženja koje je poslalo poruku na adresi `dstva`
- imati id okruženja koje je poslalo poruku zapisan u `env_ipc_from` u svom `struct Env` iz niza `envs`
- imati permisije koje ima za pristup mapiranoj stranici zapisane u `env_ipc_perm` u svom `struct Env` iz niza `envs`

Slijedi implementacija ovog sistemskog poziva:
``` c
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void* srcva, unsigned perm)
{
  struct Env* env_recv; // receiving environment

  if (envid2env(envid, &env_recv, 0))
    return -E_BAD_ENV;

  if (!env_recv->env_ipc_recving)
    return -E_IPC_NOT_RECV;

  env_recv->env_ipc_perm = 0; // updates again if a page is sent

  // if addresses are in user part of memory try to send a page
  if ((uintptr_t)srcva < UTOP && (uintptr_t)env_recv->env_ipc_dstva < UTOP)
  {
    if ((uintptr_t)srcva % PGSIZE)
      return -E_INVAL;

    if (perm & ~PTE_SYSCALL)
      return -E_INVAL;

    pte_t* pte;
    struct PageInfo* page;

    pte = NULL; // initialize because page_lookup does not update it if page is not found
    page = page_lookup(curenv->env_pgdir, srcva, &pte);

    if (!pte)
      return -E_INVAL;

    if (perm & PTE_W && !(*pte & PTE_W))
      return -E_INVAL;

    if (page_insert(env_recv->env_pgdir, page, env_recv->env_ipc_dstva, perm))
      return -E_NO_MEM;

    env_recv->env_ipc_perm = perm;
  }

  // set target (receiving) environment's ipc fields
  env_recv->env_ipc_recving = false;
  env_recv->env_ipc_from = curenv->env_id;
  env_recv->env_ipc_value = value;
  env_recv->env_status = ENV_RUNNABLE;

  return 0;
}
```

Ukoliko `srcva` ili `dstva` nisu u user dijelu adresnog prostora (ispod `UTOP`),
to se interpretira kao znak da nije potrebno izvršiti nikakvo mapiranje.
U suprotnom, pomoću funkcije `page_lookup` se nalazi stranica koja je mapirana na adresu `srcva`
i ista se mapira u adresni prostor okruženja koje prima poruku pomoću funkcije `page_insert`
sa permisijama `perm` koje su date kao argument sistemskog poziva.


### `syscall` dispatch
Kako bi se mogli koristiti novo-implementirani sistemski pozivi potrebno je 
dodati dispatch za njih u funkciji `syscall` u fajlu [`syscall.c`](../kern/syscall.c):
``` c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
  switch (syscallno)
  {
                        ...
  case SYS_ipc_try_send:
    return sys_ipc_try_send(a1, a2, (void*)a3, a4);
  case SYS_ipc_recv:
    return sys_ipc_recv((void*)a1);
  }
}
```


### `ipc_send`
Ova funkcija služi kao wrapper za sistemski poziv `sys_ipc_try_send`.
Sve što radi je jednostavno pokušava poslati poruku nekom drugom okruženju
sve dok slanje ne uspije ili dok se ne desi neki error.
``` c
void
ipc_send(envid_t to_env, uint32_t val, void* pg, int perm)
{
  int err;

  if (pg == NULL)
    pg = (void*)UTOP;

  while ((err = sys_ipc_try_send(to_env, val, pg, perm)))
    if (err != -E_IPC_NOT_RECV) // gets to here only of there's an error
      panic("ipc_send: %e", err);
}
```

U implementaciji `sys_ipc_try_send` spomenuto je da ukoliko adresa za `srcva`
nije iz user dijela adresnog prostora, to se interpretira kao znak da nije potrebno mapirati stranicu.
U ovoj funkciji, ako je `pg` `NULL` pointer, to ima isto značenje,
pa se u tom slučaju `pg` postavi na `UTOP` (može i bilo koja adresa iznad `UTOP`) kao znak
sistemskom pozivu da ne vrši mapiranje.


### `ipc_recv`
Ova funkcija služi kao wrapper za sistemski poziv `sys_ipc_recv`.
Također kroz pointere `from_env_store` i `perm_store` pohranjuje informacije od kojeg okruženja
je dato okruženje primilo poruku i koje permisije ima za pristup mapiranoj stranici, respektivno.
``` c
int32_t
ipc_recv(envid_t* from_env_store, void* pg, int* perm_store)
{
  int err;

  if (pg == NULL)
    pg = (void*)UTOP;

  if ((err = sys_ipc_recv(pg)))
  {
    // ipc_recv syscall failed

    if (from_env_store)
      *from_env_store = 0;

    if (perm_store)
      *perm_store = 0;

    return err;
  }
  else
  {
    // ipc_recv syscall succeeded

    if (from_env_store)
      *from_env_store = thisenv->env_ipc_from;

    if (perm_store)
      *perm_store = thisenv->env_ipc_perm;

    return thisenv->env_ipc_value;
  }
}
```

U slučaju da primanje poruke ne uspije, funkcija vraća error koji dobije od sistemskog poziva,
a za podatke o tome ko je poslat poruku i koje permisije ima zapisuje vrijednost `0`.
U suprotnom, ako primanje poruke uspije, na adrese na koje pokazuju pointeri `from_env_store` i `perm_store` 
zapisuje vrijednosti iz svog `struct Env` iz niza `envs` (osnosno `thisenv`), 
koje je tamo spremilo okruženje koje je slalo poruku u sistemskom pozivu `sys_ipc_try_send`,
a funkcija vraća vrijednost koju je okruženje primilo.
Pri zapisivanju vrijednosti u pointere `from_env_store` i `perm_store` bitno je provjeriti da li su oni `NULL` pointeri.


## Challenge 8
Uklonjena je petlja u funkciji `ipc_send`, reimplementiarn je dispatch za sistemski poziv `sys_ipc_try_send`
i implementirana je funkcionalnost gdje okruženje koje želi poslati poruku ne koristi CPU sve dok okruženje kojem
šalje poruku ne bude spremno da je primi.


## Challenge 9
Implementiran program [`ipcmatrixmult`](../user/ipcmatrixmult.c) koji vrši množenje stream-a ulaznih vektora sa matricom na osnovu 
[*C. A. R. Hoare, "Communicating Sequential Processes"*](https://dl.acm.org/doi/pdf/10.1145/359576.359585#page=9).
Implementiran je na način da je moguće koristiti matricu (i vektore) proizvoljnog reda, umjesto samo 3x3.
