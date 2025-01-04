<div align='center'><h1 align='center'>Part A: User Environments and Exception Handling</h1></div>

# Allocating the Environments Array

## Exercise 1

Alokacija prostora za `envs` se može uraditi pomoću funkcije `boot_alloc`.
`boot_alloc` se smije koristiti jer se poziva prije funkcije `page_init`.
Potrebno je alocirati dovoljno memorije za `NENV` okruženja,
pa je broj bajti koji će se alocirati `NENV` puta veličina jednog okruženja `struct Env`.
Također, sva okruženja su nulirana (svi bajti postavljeni na nula).
Rezultat toga će biti da svako polje svkog `struct Env` iz `envs` ima vrijednost `NULL`,
što će smanjiti vjerovatnoću pojave bugova koji su teški za identificiranje.

``` c
envs = (struct Env*)boot_alloc(sizeof(struct Env) * NENV);
memset(envs, 0, sizeof(struct Env) * NENV);
```

Mapiranje se može izvršiti pomoću funkcije `boot_map_region`, na sličan način kao u [lab2](./answers_2.md).
Sva okruženja se mapiraju u virtuelnu memoriju počevši od adrese `UENVS`.
U ovom trenutku se koristi inicijalno mapiranje za kernel (4MB od `0x0` i `KERNBASE` virtuelne memorije na `0x0` fizičke memorije),
pa pomoću `PADDR` se dobija fizička adresa na kojoj se nalaze okruženja (`envs`).
Budući da se radi o user okruženjima, potrebno je omogućiti pristup ovom mapiranju iz user mode, 
pa se kao argument za `perm` prosljeđuje `PTE_U` (`PTE_P` je uvijek setovan u funkciji `boot_map_region`).
``` c
boot_map_region(kern_pgdir, UENVS, sizeof(struct Env) * NENV, PADDR(envs), PTE_U);
```

Korisnički programi će pristupati `pages` sa dijela virtuelne memorije od `UPAGES`.
To mapiranje se također kreira pomoću `boot_map_region`, pri čemu se kao `perm` prosljeđuje `PTE_U`.
Ne želimo da korisnički programi mogu mijenjati `pages`, pa se ne koristi `PTE_W`.
``` c
boot_map_region(kern_pgdir, UPAGES, sizeof(struct PageInfo) * npages, PADDR(pages), PTE_U);
```


## Exercise 2

### `env_init`
Ova funkcija inicijalizira okruženja (`envs`) i linkanu listu slobodnih okruženja (`env_free_list`).

Budući da je u ***Exercise 1*** svako polje svakog okruženja postavljeno na `NULL`,
to nije potrebno ovdje ponovo raditi.
Svaki `env_status` će već biti postavljen na `ENV_FREE` (`0`) i
svaki `env_id` će biti `0`.
Dakle, samo je potrebno kreirati linkanu listu slobodnih okruženja.

Budući da je `env_free_list` globalna neinicijalizirana varijabla, ona će se nalaziti u `.bss` sekciji kernela.
Bootloader je nulirao cijelu `.bss` sekciju kernela, pa će `env_free_list` imati vrijednost `NULL`,
što će označavati kraj liste slobodnih okruženja (ako `env_free_list` ikad bude `NULL` nema više slobodnih okruženja).
Linkana lista slobodnih okruženja (`env_free_list`) će se kreirati na sličan način kao i linkana lista slobodnih stranica (`page_free_list`).
Jedan bitan detalj, naveden u komentaru iznad `env_init`, je da inicijalno `env_free_list` mora pokazivati na `envs[0]`,
odnosno prvi element niza `envs` mora biti prvi element linkane liste `env_free_list`, drugi mora biti drugi, itd.
Na ovaj način se osigurava da prva alokacija okruženja vrati prvo okruženje (`envs[0]`).

``` c
void env_init(void)
{
  for (int i = NENV - 1; i >= 0; --i)
  {
    envs[i].env_link = env_free_list;
    env_free_list = &envs[i];
  }
               ...
}
```

### `env_setup_vm`
Ova funkcija postavlja mapiranje virtuelne memorije (page directory) za dato okruženje.

Dio ove funkcije je već napisan.
Alocira se novi okvir koji će se koristiti za page directory od datog okruženja (`e`),
pri čemu se cijeli okvir nulira i provjerava se da li je alokacija uspjela.

Potrebno je inkrementirati broj referenci na novi okvir, jer funkcija `page_alloc` to ne radi automatski.

Nakon toga se kaže datom okruženju gdje mu je page directory.
Za dobijanje virtuelne adrese okvira u kojem će biti page directory datog okruženja se koristi funkcija `page2kva`.

Svako okruženje treba imati kernel iznad `KERNBASE`,
tako da se kao template za kreiranje page directory okruženja može koristiti kernel page directory (`kern_pgdir`).
Iz tog razloga, koristi se `memcpy` kako bi se napravila kopija `kern_pgdir` u `env_pgdir` od datog okruženja.
Na kraju se mijenja mapiranje stranice sa virtuelne adrese `UVPT` sa `kern_pgdir` na `env_pgdir` datog okruženja, sa user permisijama.

Ispod je označen dio koda koji sam ja implementirao.
``` c
static int
env_setup_vm(struct Env* e)
{
  int i;
  struct PageInfo* p = NULL;

  if (!(p = page_alloc(ALLOC_ZERO)))
    return -E_NO_MEM;

////////////////////////////////////////////////////////////////
  ++p->pp_ref;
  e->env_pgdir = page2kva(p);
  memcpy(e->env_pgdir, kern_pgdir, PGSIZE);
////////////////////////////////////////////////////////////////

  e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;

  return 0;
}
```


### `region_alloc`
Ova funkcija alocira `len` bajti koji će biti mapirani u virtuelnu memoriju počevši od adrese `va`, za okruženje `e`.

Vrijednosti `va` i `len` nisu nužno poravnate na veličinu stranice (`PGSIZE`), pa je potrebno to uraditi.
Za `va` je potrebno koristiti `ROUNDDOWN`. Ako bi koristili `ROUNDUP` tada `va` ne bi bilo mapirano jer bi prva mapirana stranica bila na adresi `va + PGSIZE`.
Za `len` je potrebno koristiti `ROUNDUP`. Ako bi koristili `ROUNDDOWN` tada bi bilo mapirano manje memorije nego što je zahtijevano.

Korisnički program ne bi smio mapirati ništa iznad `UTOP`, pa je to potrebno provjeriti.

`pages_n` je broj stranica koje je potrebno alocirati \
`pages_size` je broj bajti koliko zauzima `pages_n` stranica

Zatim je za svaku stranicu potrebno alocirati okvir i mapirati ga u tu stranicu.
Okvir se alocira pomoću `page_alloc`, a mapiranje se vrši pomoću funkcije `page_insert`.
Kao permisije se koriste `PTE_U` jer će tu stranicu koristiti korisnički program 
i `PTE_W` jer želimo omogućiti korisničkom programu mogućnost modifikacije memorije.
Potrebno je provjeriti da li su alokacije uspjele.
Nije potrebno inkrementovati `pp_ref` alocirane stranice jer to radi `page_insert`.

``` c
static void
region_alloc(struct Env* e, void* va, size_t len)
{
  size_t pages_n;    // number of pages that need to be allocated
  size_t pages_size; // size of pages that need to be allocated

  va = ROUNDDOWN(va, PGSIZE);
  pages_size = ROUNDUP(len, PGSIZE);
  pages_n = pages_size / PGSIZE;

  // sanity check
  if ((size_t)va + pages_size > UTOP)
    panic("region_alloc: requested too much memory");

  for (int i = 0; i < pages_n; ++i)
  {
    struct PageInfo* page;

    // allocate page for enviroment
    if (!(page = page_alloc(0)))
      panic("region_alloc: page allocation failed");

    // map allocated page for environment
    // also increments pp_ref
    if (page_insert(e->env_pgdir, page, va, PTE_U | PTE_W))
      panic("region_alloc: page table allocation failed");

    va += PGSIZE;
  }
}
```


### `load_icode`
Ova funkcija učitaje kod i podatke programa (`binary`), inicijalizira stack i entry point za dato okruženje (`e`).

Na početku svakog ELF fajla se nalazi ELF header, u kojem se nalazi `ELF_MAGIC` string.
Kastiranjem `binary` u `struct Elf*` se početak programa interpretira kao ELF header.
Potrebno je provjeriti da li je proslijeđeni program u ELF formatu, što se radi provjeravanjem `e_magic`.

Za učitavanje programa potrebno je koristiti virtuelni adresni prostor od procesa (okruženja) za koji se program učitaje (`e`).
Virtuelni adresni prostor se mijenja promjenom page directory, što se radi promjenom adrese zapisane u registar `%cr3` pomoću funkcije `lcr3`.

Program header sadrži informacije o sekcijama koje je potrebno učitati u memoriju.
Prvi program header se nalazi na `e_phoff` nakon početka fajla (`binary`).

Dalje, za svaki program header se provjerava da li je tipa `LOAD` i preskače se ako nije.
Vrijednost `p_filesz` nikada ne bi smjela biti veća od `p_memsz`, pa se u tom slučaju poziva `panic`.

Zatim slijedi samo učitavanje programa u memoriju.
Prvo se mora alocirati memorija gdje će se program učitati.
Nakon alokacije kopira se sadržaj fajla u memoriju.
Na kraju se `.bss` sekcija popuni nulama.
Time je program učitan u memoriju.

Kako bi se program mogao početi izvršavati, potrebno je da kernel zna gdje je entry point od programa.
Taj podatak se zapisuje unutar trap frame-a (`env_tf`) od datog okruženja (`e`).
Trap frame sadrži polje `tf_eip`, čiju će vrijednost kernel učitati u registar `%eip` kada se počne izvršavati okruženje `e`.
U to polje se zapisuje entry point programa, čija se vrijednost čita iz ELF headera (`elfh->e_entry`).
Na kraju se mapira jedna stranica za stack od datog okruženja (`e`) i vraća se na kernel page directory.

``` c
static void
load_icode(struct Env* e, uint8_t* binary)
{
  struct Elf* elfh = (struct Elf*)binary; // pointer to ELF header
  struct Proghdr* ph;                     // pointer to program header

  if (elfh->e_magic != ELF_MAGIC)
    panic("load_icode: binary is not ELF");

  // using enviroment page directory
  lcr3(PADDR(e->env_pgdir));

  // address of first header
  ph = (struct Proghdr*)(binary + elfh->e_phoff);

  for (int i = 0; i < elfh->e_phnum; ++i, ++ph)
  {
    // skip non-LOAD headers
    if (ph->p_type != ELF_PROG_LOAD)
      continue;

    // sanity check
    if (ph->p_filesz > ph->p_memsz)
      panic("load_icode: program header filesz can't be greater than memsz");

    // allocate memory for program
    region_alloc(e, (void*)ph->p_va, ph->p_memsz);

    // copy program from binary into memory
    memcpy((void*)ph->p_va, (void*)(binary + ph->p_offset), ph->p_filesz);

    // clear .bss section
    memset((void*)(ph->p_va + ph->p_filesz), 0, ph->p_memsz - ph->p_filesz);
  }

  // setup entry point
  e->env_tf.tf_eip = elfh->e_entry;

  // map one page for the program's initial stack
  region_alloc(e, (void*)(USTACKTOP - PGSIZE), PGSIZE);

  // go back to kernel page directory
  lcr3(PADDR(kern_pgdir));
}
```


### `env_create`
Ova funkcija kreira novo okruženje tipa `type` i u njega učita program koji počinje od `binary`.

Alocira se novo okruženje pomoću funkcije `env_alloc`, pri čemu se provjerava da li je alokacija uspjela.
Zatim se učitaje program u novo-alocirano okruženje i postavlja se tip okruženja.

``` c
void env_create(uint8_t* binary, enum EnvType type)
{
  struct Env* env;

  // makes a new enviroment and sets up vm
  if (env_alloc(&env, 0))
    panic("env_create: enviroment allocation failed");
  load_icode(env, binary);

  env->env_type = type;
}
```


### `env_run`
Ova funkcija pokreće okruženje koje je proslijeđeno funkciji putem parametra `e`.

Globalna varijabla `curenv` govori koje okruženje se trenutno izvršava.
Ako se neko drugo okruženje trenutno koristi potrebno je promijeniti mu stanje u `ENV_RUNNABLE`,
jer se nakon poziva ove funkcije ono više neće izvršavati.
Stanje se mijenja u `ENV_RUNNABLE` jer je ono i dalje spremno da se izvršava.

Pomoću varijable `curenv` potrebno je reći da se od sada izvršava okruženje `e`,
te je potrebno promijeniti njegov status u `ENV_RUNNING`.
Dalje, inkrementuje se brojač `env_run` koji govori koliko puta je dato okruženje pokrenuto.

Potrebno je reći procesoru da od sada koristi virtuelni adresni prostor datog okruženja (`e`),
što se radi učitavanjem fizičke adrese page directory tog okruženja u registar `%cr3`, pomoću funkcije `lcr3`.

Na kraju, kako bi se okruženje počelo izvršavati, 
potrebno je sve registre iz trap frame-a (`env_tf`) datog okruženja učitati u procesor.
To se radi pomoću funkcije `env_pop_tf`.
Nikada se ne bi trebao desiti povratak iz funkcije `env_pop_tf` 
i ukoliko se desi to znači da se desila greška pri pokretanju okruženja.

``` c
void env_run(struct Env* e)
{
  if (curenv) // enviroment already running
  {
    if (curenv->env_status == ENV_RUNNING)
      curenv->env_status = ENV_RUNNABLE;
  }

  curenv = e;
  curenv->env_status = ENV_RUNNING;
  ++curenv->env_runs;
  lcr3(PADDR(e->env_pgdir));

  env_pop_tf(&e->env_tf);

  // should never get here
  panic("env_run not yet implemented");
}
```

***Zašto se nikada ne bi trebao desiti povratak iz funkcije `env_pop_tf`?***

Zato jer se nakon poziva te funkcije direktno mijenjaju svi registri procesora, kao i stack koji se koristi.
Promjenom registra `%eip` se mijenja tok programa.
Promjenom registra `%cs` se mijenja aktuelni deskriptor i nivo privilegija.
Promjenom registara `%ss` i `%esp` se mijenja aktuelni stack.

Pogledajmo definiciju funkcije `env_pop_tf`.
``` c
void env_pop_tf(struct Trapframe* tf)
{
  asm volatile(
    "\tmovl %0,%%esp\n"
    "\tpopal\n"
    "\tpopl %%es\n"
    "\tpopl %%ds\n"
    "\taddl $0x8,%%esp\n" /* skip tf_trapno and tf_errcode */
    "\tiret\n"
    : : "g"(tf) : "memory");
  panic("iret failed"); /* mostly to placate the compiler */
}
```

Funkcija `env_pop_tf` direktno poziva asembler. 
Kao zadnja instrukcija u ovoj funkciji izvršava se instrukcija `iret`.
Dakle, između ostalog, pozivom ove funkcije procesor se "predaje" korisničkoj aplikaciji čije se okruženje pokreće.

Zbog navedenih razloga, praktično se gubi cijela metodologija po kojoj bi se nastavilo izvršavanje koda nakon poziva ove funkcije.
Jasno je da se povratak iz funkcije `env_pop_tf` nikada ne bi smio desiti.


### GDB analiza
Prilikom pokretanja JOS-a počinje se izvršavati korisnički program *hello*.
U disasembliranom programu *hello* (`hello.asm`) se nalazi sljedeći kod:
``` asm
                     ...
void sys_cputs(const char* s, size_t len)
{
                     ...
  800bc3:	cd 30                	int    $0x30
  syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
}
                     ...
```

Unutar programa *hello* se poziva funkcija `sys_cputs` koja koristi sistemski poziv da nešto isprinta.
Budući da trenutno ne postoji nikakav oblik tretiranja prekida, sistemski poziv se neće moći adekvatno tretirati.
Zbog toga, očekuje se da se kao rezultat sistemskog poziva baci iznimka.
Budući da tu iznimku iz istih razloga niko ne tretira, desit će se još jedna iznimka.
To je već treći prekid koji se ne tretira.
Ukoliko se dese tri netretirana prekida (triple fault) sistem će se restartovati.
Dakle, nakon instrukcije `int $0x30` očekuje se restartovanje računara (QEMU-a).

Iz prethodnog koda se može pročitati adresa na kojoj se nalazi instrukcija `int $0x30`, a to je `0x800bc3`.

Kako bi se uvjerili da se program *hello* stvarno počne izvršavati i 
dođe do pomenute `int` instrukcije postavlja se breakpoint na pročitanu adresu:
```
(gdb) b *0x800bc3
Breakpoint 1 at 0x800bc3
```

Ako se sistem pokrene i pusti da izvršava, dolazi se do postavljenog breakpointa:
```
(gdb) continue
Continuing.
=> 0x800bc3:    int    $0x30

Breakpoint 1, 0x00800bc3 in ?? ()
```

Dalje, ukoliko se nastavi izvršavanje, očekuje se restartovanje sistema.
Kako bi se uvjerili da se sistem stvarno restartuje, 
postavit će se breakpoint na prvu instrukcije kernela, koja je na adresi `0x10000c`:
```
(gdb) b *0x10000c
Breakpoint 2 at 0x10000c
```

Ako se nastavi sa izvršavanjem:
```
(gdb) continue
Continuing.
=> 0x10000c:    movw   $0x1234,0x472

Breakpoint 2, 0x0010000c in ?? ()
```
GDB se zaustavlja na instrukciji koja je na adresi `0x10000c`.
Dakle, sistem se ponovo pokreće.
Ako dalje nastavi sa izvršavanjem:
```
(gdb) continue
Continuing.
=> 0x800bc3:    int    $0x30

Breakpoint 1, 0x00800bc3 in ?? ()
```
GDB se zaustavlja na sistemskom pozivu, kao u prvom slučaju.

Ovo je upravo ono što se i treba desiti.


## Exercise 3

Pročitan [chapter 9](https://pdos.csail.mit.edu/6.828/2018/readings/i386/c09.htm).


## Exercise 4

U [`trap.c`](../kern/trap.c) su deklarisani trap handleri za iznimke, prema nazivima u [`trap.h`](../inc/trap.h).
``` c
void th_divide();
void th_debug();
void th_nmi();
void th_brkpt();
void th_oflow();
void th_bound();
void th_illop();
void th_device();
void th_dblflt();
// void th_coproc();
void th_tss();
void th_segnp();
void th_stack();
void th_gpflt();
void th_pgflt();
// void th_res();
void th_fperr();
void th_align();
void th_mchk();
void th_simderr();
```
Zakomentarisane deklaracije su rezervirane i neće se koristiti.

Korištenjem [Table 5-1](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-3A.pdf#page=185) 
iz [Intel Manual](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-3A.pdf)-a
napisani su sljedeći trap handleri:
``` asm
TRAPHANDLER_NOEC(th_divide,  T_DIVIDE)
TRAPHANDLER_NOEC(th_debug,   T_DEBUG)
TRAPHANDLER_NOEC(th_nmi,     T_NMI)
TRAPHANDLER_NOEC(th_brkpt,   T_BRKPT)
TRAPHANDLER_NOEC(th_oflow,   T_OFLOW)
TRAPHANDLER_NOEC(th_bound,   T_BOUND)
TRAPHANDLER_NOEC(th_illop,   T_ILLOP)
TRAPHANDLER_NOEC(th_device,  T_DEVICE)
TRAPHANDLER     (th_dblflt,  T_DBLFLT)
# TRAPHANDLER_NOEC(th_coproc,  T_COPROC)
TRAPHANDLER     (th_tss,     T_TSS)
TRAPHANDLER     (th_segnp,   T_SEGNP)
TRAPHANDLER     (th_stack,   T_STACK)
TRAPHANDLER     (th_gpflt,   T_GPFLT)
TRAPHANDLER     (th_pgflt,   T_PGFLT)
# TRAPHANDLER_NOEC(th_res,     T_RES)
TRAPHANDLER_NOEC(th_fperr,   T_FPERR)
TRAPHANDLER     (th_align,   T_ALIGN)
TRAPHANDLER_NOEC(th_mchk,    T_MCHK)
TRAPHANDLER_NOEC(th_simderr, T_SIMDERR)
```
Prvi argument makroa `TRAPHANDLER` i `TRAPHANDLER_NOEC` je pointer na funkciju koja će se koristiti za tretiranje tog prekida.
Drugi argument obih makroa je redni broj (vektor) prekida.
Ove kontante su definisane u [`trap.h`](../inc/trap.h).
Razlika između ovih makroa je u tome što se `TRAPHANDLER` koristi za prekide za koje procesor na stack pusha error code,
a `TRAPHANDLER_NOEC` se koristi za prekide koji nemaju error code i umjesto toga se na stack pusha `0`, 
kako bi se prezervirala ista struktura za sve trap frame-ove.
Kao i u C kodu, zakomentarisani handleri su rezervirani i ne koriste se.

Dalje, inicijaliziran je IDT u funkciji `trap_init`:
``` c
  SETGATE(idt[T_DIVIDE],  0, GD_KT, th_divide , 0);  
  SETGATE(idt[T_DEBUG],   0, GD_KT, th_debug  , 0);
  SETGATE(idt[T_NMI],     0, GD_KT, th_nmi    , 0);
  SETGATE(idt[T_BRKPT],   0, GD_KT, th_brkpt  , 0);
  SETGATE(idt[T_OFLOW],   0, GD_KT, th_oflow  , 0);
  SETGATE(idt[T_BOUND],   0, GD_KT, th_bound  , 0);
  SETGATE(idt[T_ILLOP],   0, GD_KT, th_illop  , 0);
  SETGATE(idt[T_DEVICE],  0, GD_KT, th_device , 0);
  SETGATE(idt[T_DBLFLT],  0, GD_KT, th_dblflt , 0);
//SETGATE(idt[T_COPROC],  0, GD_KT, th_coproc , 0);
  SETGATE(idt[T_TSS],     0, GD_KT, th_tss    , 0);
  SETGATE(idt[T_SEGNP],   0, GD_KT, th_segnp  , 0);
  SETGATE(idt[T_STACK],   0, GD_KT, th_stack  , 0);
  SETGATE(idt[T_GPFLT],   0, GD_KT, th_gpflt  , 0);
  SETGATE(idt[T_PGFLT],   0, GD_KT, th_pgflt  , 0);
//SETGATE(idt[T_RES],     0, GD_KT, th_res    , 0);
  SETGATE(idt[T_FPERR],   0, GD_KT, th_fperr  , 0);
  SETGATE(idt[T_ALIGN],   0, GD_KT, th_align  , 0);
  SETGATE(idt[T_MCHK],    0, GD_KT, th_mchk   , 0);
  SETGATE(idt[T_SIMDERR], 0, GD_KT, th_simderr, 0);
```
Za ovu namjenu se koristi makro `SETGATE`.
Makro `SETGATE` popunjava polja IDT deskriptora (gate).

Pogledajmo njegove parametre (iz fajla [`mmu.h`](../inc/mmu.h)):
``` c
#define SETGATE(gate, istrap, sel, off, dpl)
```

Kao prvi argument se prosljeđuje gate čija se polja popunjavaju.
U fajlu [`trap.c`](../kern/trap.c) se nalazi globalna varijabla `idt` koja služi za inicijalizaciju IDT, 
i predstavlja niz od 256 gate deskriptora (`struct Gatedesc`).
U ovom slučaju `gate` je element iz niza `idt`, koji se indeksira pomoću vektora `T_*` definisanih u [`trap.h`](../inc/trap.h).

Drugi argument govori da li je taj gate trap gate (`1`) ili interrupt gate (`0`).
Trap gate resetuje `IF` (Interrupt Flag) u flags registru (`eflags`) 
i time onemogućava tretiranje novog prekida dok se neki već tretira,
dok interrupt gate ne mijenja `IF`.
Želimo da u ovom slučaju JOS bude preemptivan, pa će se kao argument koristiti vrijednost `0`.

Treći argument je code segment selektor.
Budući da se iznimke tretiraju u kernel modu, koristit će se selektor za kernel code segment.
U fajlu [`memlayout.h`](../inc/memlayout.h) se nalaze definicije za različite selektore koji se koriste u JOS-u.
Kernel code segment selektor je definisan kao `GD_KT`, pa se ta vrijednost ovdje koristi.

Četvrti argument je offset unutar korištenog code segmenta (u ovom slučaju kernel code segmenta) koji pokazuje na entry point datog trap handler-a.
Budući da JOS koristi flat model segmentacije, to će zapravo predstavljati neku virtuelnu adresu.
Ta virtuelna adresa će biti pointer na funkciju koja tretira dati prekid, a to su funkcije `th_*`.

Peti argument je DPL, odnosno potrebni nivo privilegija.
U ovom slučaju to se odnosi na nivo privilegija potreban da se dati prekid pozove pomoću instrukcije `int`.
Budući da ne želimo da koristički programi proizvoljno generišu iznimke, 
kao argument će se koristiti vrijednost `0`, 
koja predstavlja kernel nivo privilegija.

Na kraju je implementirana funkcija `_alltraps` u fajlu [`trapentry.S`](../kern/trapentry.S):
``` asm
_alltraps:
  # save registers
  pushl %ds
  pushl %es
  pushal
  # load kernel code selector into %ds and %es
  movw $GD_KD, %ax
  movw %ax, %ds
  movw %ax, %es
  # prepare pointer to trap frame as argument
  pushl %esp
  # handle trap
  call trap
```

Budući da instrukcija `pushal` (negdje nazvana [`pushad`](https://pdos.csail.mit.edu/6.828/2018/readings/i386/PUSHA.htm)) ne pusha segmentne registre,
potrebno je prezervirati registre `%ds` i `%es` na stacku prije poziva `pushal`.
Konstante se ne mogu direktno učitavati u segmentne registre, pa je to potrebno uraditi pomoću registra opšte namjene.
U ovom slučaju proizvoljno je odabran registar `%ax` (ne `%eax` zato jer su segmentni registri 16-bitni).
Funkcija `trap`, definisana u [`trap.c`](../kern/trap.c) kao argument prima pointer na `struct Trapframe`.
Ovaj argument je potrebno pripremiti na stacku.
Budući da je taj trap frame upravo napravljen na stacku, 
kao argument se jednostavno proslijedi trenutna vrijednost `%esp` 
tako što se ona pusha na stack prije poziva funkcije `trap`.


## Challenge 1
Cilje je da se smanji količina (sličnog) koda.
U tu svrhu izbacit će se deklaracije `th_*` funkcija iz [`trap.c`](../kern/trap.c) 
i silnih `SETGATE` makroa u funkciji `trap_init` u istom fajlu.

Trap handeri (funkcije) su definisane u asembleru.
Unutar asemblera su poznate adrese (pointeri) tih funkcija.
Te adrese će biti spremljene kao niz u `.data` sekciji kernela.
Zatim, unutar funkcije `trap_init` se može iskoristiti taj niz kako bi se pomoću petlje i makroa `SETGATE` inicijalizirao IDT.

Naziv niza trap handlera će biti `_trap_handlers`, definisan u [`trapentry.S`](../kern/trapentry.S):
``` asm
.data
.global _trap_handlers
_trap_handlers:
```

Makroi `TRAPHANDLER*` su modifikovani tako da dodaju adresu trenutnog trap handler-a u `.data` sekciju:
``` asm
#define TRAPHANDLER(name, num)                                  \
.data;                                                          \
  .long name;                                                   \
.text;                                                          \
  .globl name;            /* define global symbol for 'name' */ \
  .type name, @function;  /* symbol type is function */         \
  .align 2;               /* align function definition */       \
  name:                   /* function starts here */            \
  pushl $(num);                                                 \
  jmp _alltraps
```
Makro `TRAPHANDLER_NOEC` je modifikovan na isti način.

Zbog lakšeg indeksiranja `_trap_handlers`, na mjesta rezerviranih trap-ova 
dodan je padding od 4B (veličina jednog pointera) koji je definisan na sljedeći način:
``` asm
#define PADDING_4B  \
  .data;            \
    .long 0x0;      \
  .text
```

Konačno, trap handleri su napravljeni na sljedeći način:
``` asm
.data
.global _trap_handlers
_trap_handlers:
.text
# order is important
TRAPHANDLER_NOEC(th_divide,  T_DIVIDE)
TRAPHANDLER_NOEC(th_debug,   T_DEBUG)
TRAPHANDLER_NOEC(th_nmi,     T_NMI)
TRAPHANDLER_NOEC(th_brkpt,   T_BRKPT)
TRAPHANDLER_NOEC(th_oflow,   T_OFLOW)
TRAPHANDLER_NOEC(th_bound,   T_BOUND)
TRAPHANDLER_NOEC(th_illop,   T_ILLOP)
TRAPHANDLER_NOEC(th_device,  T_DEVICE)
TRAPHANDLER     (th_dblflt,  T_DBLFLT)
PADDING_4B 
# TRAPHANDLER_NOEC(th_coproc,  T_COPROC)
TRAPHANDLER     (th_tss,     T_TSS)
TRAPHANDLER     (th_segnp,   T_SEGNP)
TRAPHANDLER     (th_stack,   T_STACK)
TRAPHANDLER     (th_gpflt,   T_GPFLT)
TRAPHANDLER     (th_pgflt,   T_PGFLT)
PADDING_4B 
# TRAPHANDLER_NOEC(th_res,     T_RES)
TRAPHANDLER_NOEC(th_fperr,   T_FPERR)
TRAPHANDLER     (th_align,   T_ALIGN)
TRAPHANDLER_NOEC(th_mchk,    T_MCHK)
TRAPHANDLER_NOEC(th_simderr, T_SIMDERR)
```

Dalje, u funkciji `trap_init`, u fajlu [`trap.c`](../kern/trap.c) IDT je inicijaliziran petljom:
``` c
void trap_init(void)
{
  extern struct Segdesc gdt[];
  extern uint32_t* _trap_handlers[];

  for (int t = T_DIVIDE; t <= T_SIMDERR; ++t)
  {
    // skip reserved traps
    if (t == T_COPROC || t == T_RES)
      continue;

    SETGATE(idt[t], 0, GD_KT, _trap_handlers[t], 0);
  }

  // Per-CPU setup
  trap_init_percpu();
}
```

Unutar funkcije je dodana deklaracija za `_trap_handlers` kao niz `uint32_t*`.
Koristi se `uint32_t` jer je to veličina jednog pointera.
Također je moguće koristiti `void*` ili slično.
Petlja dodaje gate deskriptor za svaki trap od `T_DIVIDE` do `T_SIMDERR`, 
pri čemu preskače rezervirane trapove `T_COPROC` i `T_RES`.

Kako bi se konstante `T_COPROC` i `T_RES` mogle koristiti, 
u fajlu [`trap.h`](../inc/trap.h) njihove definicije su odkomentarisane:
``` c
// Trap numbers
                    ...
#define T_COPROC     9    // reserved (not generated by recent processors)
                    ...
#define T_RES        15   // reserved
                    ...
```

Također su izbrisane deklaracije funkcija `th_*` iz [`trap.c`](../kern/trap.c).


## Question 1
#### What is the purpose of having an individual handler function for each exception/interrupt? (i.e., if all exceptions/interrupts were delivered to the same handler, what feature that exists in the current implementation could not be provided?)
Ako bi se koristio samo jedan handler, tada ne bi mogli razlikovati prekide, niti bi mogli imati istu strukturu za sve trap frame-ove.

Uzmimo za primjer slučaj da svi prekidi koriste jedan handler.
Tada svi vektori u IDT pokazuju na istu funkciju (npr. `_alltraps`).
Procesor dobija prekid i ulazi u funkciju `_alltraps`.
Procesor na stack pusha `eflags`, `%cs`, `%eip`, i eventualno `%ss`, `%esp` i error code.
Koji prekid je dobijen?
Nema načina da se odredi koji se prekid zapravo desio.

Dalje, ako procesor pusha error code, budući da nije poznato koji se prekid uopće desio,
zapravo nije poznato ni da li je error code na stacku ili ne.
Tako da bi trap frame sa errorom imao drugačiju strukturu od trap frame-a bez errora.
Da, može se pročitati ta vrijednost i naslutiti da li je to error code ili `%eip`, ali ne možemo biti 100% sigurni.
Šta ako brojimo bajte od početka stack-a, pa na taj način odredimo da li ima error code ili ne?
Ovdje problem prestavljaju ugniježdeni prekidi. Ako se neki prekid (ili više prekida) već tretirao,
tada ne možemo znati gdje počinje stack frame za trenutni prekid.


## Question 2
#### Did you have to do anything to make the `user/softint` program behave correctly? The grade script expects it to produce a general protection fault (trap 13), but `softint`'s code says `int $14`. Why should this produce interrupt vector 13? What happens if the kernel actually allows `softint`'s `int $14` instruction to invoke the kernel's page fault handler (which is interrupt vector 14)?
U interrupt deskriptorima DPL polje označava nivo privilegija potreban da se dati prekid pozove koristeći instrukciju `int`.
Za iznimke (sve što je do sad implementirano) DPL je postavljen na 0, što znači da je potreban kernel nivo privilegija.
Trap 14, koji program poziva, spada u tu grupu.
Budući da program sa user nivoom privilegija pokuša uraditi nešto za šta je potreban kernel nivo privilegija, 
generiše se GPF (General Protection Fault, trap 13).

Može se dozvoliti user programima da pozivaju interrupte sa instrukcijom `int` promjenom `dpl` polja u `SETGATE` makrou, u funkciji `trap_init`:
``` c
void trap_init(void)
{
                        ...
  for (int t = T_DIVIDE; t <= T_SIMDERR; ++t)
  {
                        ...
    SETGATE(idt[t], 0, GD_KT, _trap_handlers[t], 3);
  }
                        ...
}
```

Dalje, kako bi se uvjeriti da ovo stvarno radi, 
umjesto `user_hello` učitajmo `user_softint`:
``` c
void i386_init(void)
{
                    ...
  ENV_CREATE(user_softint, ENV_TYPE_USER);
                    ...
  env_run(&envs[0]);
}
```

Sada `make qemu` ili `make qemu-nox` učitaje program `softint` umejsto `hello`. 
Alternativno, može se koristiti `make run-softint` ili `make run-softint-nox` kako bi se pokrenuo program `softint`.

Pokretanjem QEMU-a se dobija ispis:
```
            ...
TRAP frame at 0xefffffc0
            ...
  trap 0x0000000e Page Fault
            ...
```

Dakle, sada se desi ono što bi i očekivali, `user_softint` izaziva page fault interrupt.
Posljedica ovoga je da page fault handler zatim "uništi" okruženje koje je izazvalo page fault, 
odnosno ovime program `softint` prestaje sa izvršavanjem.



# Part B: Page Faults, Breakpoints Exceptions, and System Calls


## Exercise 5
`struct Trapframe`, definisana u [`trap.h`](../inc/trap.h), ima polje `tf_trapno` koje predstavlja broj prekida koji se desio:
``` c
struct Trapframe
{
            ...
    uint32_t tf_trapno;
            ...
} ...
```

Prema tome, na osnovu `struct Trapframe` znamo koji se prekid desio.
Kako bi svaki prekid tretirali na adekvatan način može se koristiti `switch` 
koji na osnovu `tf_trapno` polja odlučuje koji će se kod izvršiti.
U ovom slučaju, želimo page fault iznimku (`T_PGFLT`) dispatch-ovati funkciji `page_fault_handler`:
``` c
static void
trap_dispatch(struct Trapframe* tf)
{
  switch (tf->tf_trapno)
  {
  case T_PGFLT:
    page_fault_handler(tf);
    return;
  }
             ...
}
```


## Exercise 6
Na isti način kao u ***Exercise 5*** dodan je dispatch za `T_BRKPT`:
``` c
static void
trap_dispatch(struct Trapframe* tf)
{
  switch (tf->tf_trapno)
  {
        ...
  case T_BRKPT:
    monitor(tf);
    return;
  }
        ...
}
```
s tim da se u ovom slučaju poziva kernel `monitor`.

Međutim, u ovom trenutku ovo ne radi.
Umjesto breakpoint prekida generiše se GPF.
Zašto?
Zato jer se breakpoint generiše instrukcijom `int $3` iz user programa,
a DPL polje u IDT od deskriptora za breakpoint prekid je 0.
Dakle, potreban je kernel nivo privilegija da bi se generisao breakpoint prekid.
Ovo je potrebno promijeniti u `trap_init`.
Promijenjeno je na sljedeći način:
``` c
void trap_init(void)
{
                    ...
  for (int t = T_DIVIDE; t <= T_SIMDERR; ++t)
  {
                    ...
    int dpl = (t == T_BRKPT) ? 3 : 0;
    SETGATE(idt[t], 0, GD_KT, _trap_handlers[t], dpl);
  }
                    ...
}
```

Ovim se za `T_BRKPT` koristi 3 za DPL polje deskriptora.
Ako u narednim exercise-ima bude potrebe za više od par deskriptora
koji imaju DPL polje 3, određivati ću vrijednosti `dpl` pomoću `switch`-a zbog bolje čitljivosti koda.
Za sada mislim da je ovo dovoljno čitljivo i performantno.

Možda bi još bolja opcija bila da se inicijalno naprave svi deskriptori sa `SETGATE`,
a zatim rezervirani nuliraju (kako bi P bit bio 0) 
i `T_BRKPT` postavi na novu vrijednost koja ima DPL postaljen na 3,
ali smatram da je ovo čitljivije, kompaktnije i lakše za razumiti.


## Challenge 2
U registru [`eflags`](https://en.wikipedia.org/wiki/FLAGS_register) se nalazi [`TF` (Trap Flag)](https://en.wikipedia.org/wiki/Trap_flag) koji može poslužiti za debagiranje.
Ako je `TF` setovan, tada se nakon svake instrukcije generiše `T_DEBUG` interrupt.

U [monitor.c](../kern/monitor.c) su implementirane komande `singlestep` i `continue` koje simuliraju slične komande iz GDB.
Izvršenjem komande `singlestep` se setuje `TF` u trenutnom okruženju.
Nakon toga, svaka izvršena instrukcija generiše `T_DEBUG` interrupt, čiji handler (u [trap.c](../kern/trap.c)) zatim pokreće kernel monitor i ispisuje trenutno stanje procesora.
Komanda `continue` postavlja `TF` na `0` i program se nastavlja izvršavati kao i inače.
Također, ukoliko korisnik trenutno debagira program (izvršena je komanda `singlestep`) kernel monitor neće ispisivati poruke dobrodošlice i o dolazećem trap frame-u.
Ta ograničenja su implementirana u fajlovima [monitor.c](../kern/monitor.c) i [trap.c](../kern/trap.c).


## Question 3
#### The break point test case will either generate a break point exception or a general protection fault depending on how you initialized the break point entry in the IDT (i.e., your call to `SETGATE` from `trap_init`). Why? How do you need to set it up in order to get the breakpoint exception to work as specified above and what incorrect setup would cause it to trigger a general protection fault?

Ovo pitanje je više-manje odgovoreno u ***exercise 6***.
Breakpoint će se "pozivati" koristeći instrukciju `int $3`.
Instrukcija `int` generiše prekid, a `$3` se koristi kao argument jer je to broj breakpoint trap-a (`T_BRKPT`).
Ako DPL polje deskriptora koji se koristi za breakpoint ima vrijednost 0,
tada će se pomenuta instrukcija moći koristiti samo kada je procesor u kernel modu, odnosno kada CPL ima vrijednost 0.
Ako se pomenuta instrukcija pokuša izvršiti sa user nivoom privilegija (CPL je 3), tada se generiše GPF (General Protection Fault).
Dakle, ako želimo omogućiti korisničkim programima da "pozivaju" breakpointe, potrebno je DPL breakpoint deskriptora postaviti na 3.
To je upravo implementirano na kraju ***exercise 6***.


## Question 4
#### What do you think is the point of these mechanisms, particularly in light of what the `user/softint` test program does?

Poenta ovih mehanizama je zaštita.
Ovim putem se ograničava šta korisnički programi mogu uraditi, odnosno zahtijevati od kernela.
Time se osigurava da zlonamjerni korisnički programi ili korisnički programi sa bugovima (npr. pogrešan argument u instrukciji `int`)
ne mogu napraviti štetu unutar kernela, pa samim time i u ostalim programima.


## Exercise 7
Prvo je potrebno napraviti novi trap handler za syscall (sistemski poziv).
To treba uraditi u [`trapentry.S`](../kern/trapentry.S).
Budući da se trap `T_RES` ne koristi i neće se nikada koristiti,
na mjesto gdje bi on bio se dodaje trap handler za sistemski poziv,
a padding koji je tu bio se briše:
``` asm
                ...
TRAPHANDLER     (th_pgflt,   T_PGFLT)
TRAPHANDLER_NOEC(th_syscall, T_SYSCALL) # <<<<<
# TRAPHANDLER_NOEC(th_res,     T_RES)
TRAPHANDLER_NOEC(th_fperr,   T_FPERR)
                ...
```
Razlog zašto se syscall handler ubacio baš ovdje, a ne npr. posle svih ostalih je zbog indeksiranja `_trap_handlers`.
Pointeri na trap handlere se dodaju u memoriju sekvencijalno.
Dakle, ako bi htjeli indeksirati `_trap_handlers` koristeći `T_SYSCALL` (`_trap_handlers[T_SYSCALL]`)
bilo bi potrebno napraviti dovoljno paddinga da pointer na syscall trap handler stvarno bude na tom mjestu.
Taj padding bi bio velik `(T_SYSCALL - T_SIMDERR) * 4` bajti, što je u ovom slučaju 116B.
Pošto bi ovo bespotrebno koristilo memoriju, a svejedno se ne koristi memorija na indeksu `T_RES`,
odlučio sam tu ubaciti pointer na syscall trap handler.

Na osnovu toga, u funkciji `trap_init`, u fajlu [`trap.c`](../kern/trap.c) dodan je deskriptor za syscall u `idt`:
``` c
void trap_init(void)
{
                            ...
  extern uint32_t* _trap_handlers[];
  for (int t = T_DIVIDE; t <= T_SIMDERR; ++t)
  {
                            ...
  }
                            ...
  SETGATE(idt[T_SYSCALL], 0, GD_KT, _trap_handlers[T_RES], 3);
                            ...
}
```
Kao DPL se koristi `3` jer želimo omogućiti korisničkim programima da prave sistemske pozive, to i jest poenta.
Kao pointer na syscall trap handler se koristi `_trap_handlers[T_RES]` iz prethodno pojašnjenih razloga.

Dalje, u funkciju `trap_dispatch` u fajlu [`trap.c`](../kern/trap.c), potrebno je dodati dispatch za sistemske pozive.
Korisnički program smiješta broj sistemskog poziva registar `%eax`, a argumente u registre `%eax`, `%edx`, `%ecx`, `%ebx`, `%edi` i `%esi`.
Budući da se stanje procesora u trenutku prekida nalazi u trap frame-u, iz njega se mogu pročitati potrebne vrijednosti.
Broj sistemskog poziva i njegovi argumenti se prosljeđuju funkciji `syscall`.
Povratna vrijednost sistemskog poziva, kao i svih funkcija, se treba nalaziti u registru `%eax`,
pa se zato povratna vrijednost funkcije `syscall` zapisuje u trap frame na mjesto gdje je registar `%eax`.
``` c
static void
trap_dispatch(struct Trapframe* tf)
{
  switch (tf->tf_trapno)
  {
  case T_SYSCALL:
  {
    uint32_t eax = tf->tf_regs.reg_eax;
    uint32_t edx = tf->tf_regs.reg_edx;
    uint32_t ecx = tf->tf_regs.reg_ecx;
    uint32_t ebx = tf->tf_regs.reg_ebx;
    uint32_t edi = tf->tf_regs.reg_edi;
    uint32_t esi = tf->tf_regs.reg_esi;
    tf->tf_regs.reg_eax = syscall(eax, edx, ecx, ebx, edi, esi);
    return;
  }
                    ...
  }
                    ...
}
```

Na kraju, potrebno je implementirati funkciju `syscall` u fajlu [`syscall.c`](../kern/syscall.c).
Na osnovu `syscallno` se može zaključiti o kojem se sistemskom pozivu radi, te je potrebno pozvati odgovarajuću funkciju.
Povratna vrijednost iz tih funkcija se koristi kao povratna vrijednost sistemskog poziva.
Budući da funkcija `sys_cputs` ne vraća vrijednost, kao povratna vrijednost će se vratiti `0`, 
kao znak da je sistemski poziv uspješno obavljen.
U slučaju nevalidnog sistemskog poziva (sa brojem koji nije implementiran) vraća se vrijednost `-E_INVAL`.
``` c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
  switch (syscallno)
  {
  case SYS_cputs:
    sys_cputs((const char*)a1, a2);
    return 0;
  case SYS_cgetc:
    return sys_cgetc();
  case SYS_getenvid:
    return sys_getenvid();
  case SYS_env_destroy:
    return sys_env_destroy(a1);
  default:
    return -E_INVAL;
  }
}
```


## Challenge 3

### Sources
- #### `sysenter` i `sysexit`
  - [AMD64 `sysenter` & `sysexit` documentation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=237)
  - [Intel `sysenter` documentation](https://pdos.csail.mit.edu/6.1810/2018/readings/ia32/IA32-2B.pdf#page=371)
  - [Intel `sysexit` documentation](https://pdos.csail.mit.edu/6.1810/2018/readings/ia32/IA32-2B.pdf#page=375)
  - [OSDev](https://wiki.osdev.org/SYSENTER#INTEL:_SYSENTER/SYSEXIT)
  
- #### Inline assembly
  - [GCC documentation](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
  - [OSDev](https://wiki.osdev.org/Inline_Assembly)
  - [Félix Cloutier](https://www.felixcloutier.com/documents/gcc-asm.html)
  - [GCC `&&label` syntax source](https://stackoverflow.com/questions/57422768/how-get-eip-from-x86-inline-assembly-by-gcc#answer-57422876)
  
- #### MSR (Model Specific Registers)
  - [Intel documentation](https://www.intel.com/content/www/us/en/content-details/671098/intel-64-and-ia-32-architectures-software-developer-s-manual-volume-4-model-specific-registers.html)
  - [OSDev](https://wiki.osdev.org/Model_Specific_Registers)
  
- #### `wrmsr` i `rdmsr`
  - [Macro definitions](http://ftp.kh.edu.tw/Linux/SuSE/people/garloff/linux/k6mod.c)
  - [Intel `wrmsr` documentation](https://pdos.csail.mit.edu/6.1810/2018/readings/ia32/IA32-2B.pdf#page=410)
  - [Intel `rdmsr` documentation](https://pdos.csail.mit.edu/6.1810/2018/readings/ia32/IA32-2B.pdf#page=246)


## Exercise 8
`thisenv` je globalna varijabla koju ima svaki proces (okruženje) i predstavlja pointer na to okruženje u nizu `envs`.
Dakle, potrebno je na neki način indeksirati `envs` i adresu tog elementa zapisati u `thisenv`.
U fajlu [`env.h`](../inc/env.h) se nalazi makro `ENVX` koji služi za indeksiranje niza `envs`.
Kao argument za taj makro se prosljeđuje ID okruženja (`envid`).
ID okruženja se može dobiti pomoću sistemskog poziva `sys_getenvid`.
Kombinujući sve navedeno, u funkciji `libmain`, u fajlu `../lib/libmain.c`, 
se postavlja vrijednost `thisenv` za svako novo okruženje:
``` c
void libmain(int argc, char** argv)
{
  thisenv = &envs[ENVX(sys_getenvid())];
                 ...
}
```


## Exercise 9
U funkciji `trap_dispatch`, u fajlu [`trap.c`](../kern/trap.c) se određuje vrsta prekida.
Unutar page fault prekida je dodana provjera da li je procesor u kernel modu.
Najniža dva bita registra `%cs` su polje CPL koje određuje nivo privilegija procesora.
Ako su ta dva bita nula, znači da je procesor u kernel modu, 
pa u tom slučaju, nakon ispisa trap frame-a, poziva se `panic`.
``` c
static void
trap_dispatch(struct Trapframe* tf)
{
  switch (tf->tf_trapno)
  {
                ...
  case T_PGFLT:
    if ((tf->tf_cs & 0x3) == 0)
    {
      print_trapframe(tf);
      panic("Page Fault in kernel");
    }
    page_fault_handler(tf);
    return;
                ...
  }
                ...
}
```

Funkcija `user_mem_assert` se nalazi u fajlu [`pmap.c`](../kern/pmap.c) i provjerava da li dato okruženje (`env`) 
može pristupiti datom regionu memorije (od `va` do `va + len`) sa datim permisijama (`perm`).
Ako ne može, tada se okruženje uništava.
Provjera mogućnosti pristupa se delegira funkciji `user_mem_check`.
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

Funkcija `user_mem_check` je također implementirana u fajlu [`pmap.c`](../kern/pmap.c) i 
zadužena za provjeru mogućnosti pristupa memoriji.
Ako funkcija zaključi da dato okruženje (`env`) ne može pristupiti nekoj adresi,
ta adresa se zapisuje u globalnu varijablu `user_mem_check_addr` i vraća se `-E_FAULT`.

Prva provjera koju ova funkcija radi je da li je zadnja adresa kojoj se pokušava 
pristupiti unutar user dijela virtuelne memorije (ispod `ULIM`).

Dalje, počevši od prve adrese stranice u kojoj se nalazi adresa `va`,
pa do zadnje adrese kojoj se pokušava pristupiti (`end_va`),
pomoću `for` petlje prolazi se kroz sve stranice koje dati memorijski opseg `[va, va + len)` obuhvata.

Za svaku stranicu se pronalazi PTE za tu stranicu, pomoću funkcije `pgdir_walk`.
Kako bi dato okruženje moglo pristupiti toj stranici, potrebno je da page table postoji (da `pte` nije `NULL`),
da se pronađeni PTE koristi (da P bit u `pte` ima vrijednost `1`) i da pronađeni PTE ima sve permisije koje su navedene u `perm`.

U `perm`, željene permisije će na mjestima odgoravajućih flag-ova imati vrijednost `1`.
To se može iskoristiti kao maska. Koristeći tu masku, vršeći bitwise and (`&`) sa PTE "izvade" se željeni flagovi iz PTE.
Ako je vrijednost "izvađenih" flagova jednaka vrijednosti `perm`, to znači da PTE ima sve permisije iz `perm`.

Ako bilo šta od navedenog nije tačno (`pte` bude `NULL`, PTE se ne koristi ili nema permisije), tada se vraća greška.
Kao povratna vrijednost se koristi `-E_FAULT`, a u `user_mem_check_addr` se zapisuje veća adresa 
između `addr` (adrese koja se trenutno provjerava) i `va` (prve adrese kojoj okruženje pokušava pristupiti.)
Ovo se radi zbog slučaja kada proces ne može pristupiti adresi `va`, kao u programu [`buggyhello.c`](../user/buggyhello.c).
``` c
int user_mem_check(struct Env* env, const void* va, size_t len, int perm)
{
  uintptr_t _va = (uintptr_t)va; // just changed type to avoid casts for readability
  uintptr_t end_va = _va + len;

  // check if user is trying to access out of user virtual memory
  if (end_va >= ULIM)
  {
    user_mem_check_addr = _va;
    return -E_FAULT;
  }

  for (uintptr_t addr = ROUNDDOWN(_va, PGSIZE); addr < end_va; addr += PGSIZE)
  {
    pte_t* pte = pgdir_walk(env->env_pgdir, (void*)addr, 0);
    uint32_t pte_perm = *pte & perm; // extract perm permission flags from PTE

    if (!pte || pte_perm != perm || !(*pte & PTE_P))
    {
      user_mem_check_addr = addr > _va ? addr : _va; // set to larger
      return -E_FAULT;
    }
  }

  return 0;
}
```

Dalje, u fajlu [`syscall.c`](../kern/syscall.c), unutar funkcije `sys_cputs` se dodaje provjera
da li trenutno okruženje može pristupiti datoj memoriji, koristeći prethodno implementiranu funkciju `user_mem_assert`.
``` c
static void
sys_cputs(const char* s, size_t len)
{
  user_mem_assert(curenv, s, len, PTE_U); // <<<<<<
  cprintf("%.*s", len, s);
}
```

Zatim se ista provjera radi i za `stab` sekcije unutar funkcije `debuginfo_eip`, u fajlu [kdebug.c](../kern/kdebug.c).
``` c
int debuginfo_eip(uintptr_t addr, struct Eipdebuginfo* info)
{
  const struct Stab *stabs, *stab_end;
  const char *stabstr, *stabstr_end;
                ...
  if (addr >= ULIM)
  {
                ...
  }
  else
  {
    const struct UserStabData* usd = (const struct UserStabData*)USTABDATA;
                ...
    if (user_mem_check(curenv, (void*)usd, sizeof(struct UserStabData), PTE_U))
      return -1;
                ...
    if (user_mem_check(curenv, stabs, stab_end - stabs, PTE_U) 
        || user_mem_check(curenv, stabstr, stabstr_end - stabstr, PTE_U))
      return -1;
  }
                ...
  return 0;
}
```


## Exercise 10
Pokretanjem programa `evilhello` pomoću `make run-evilhello-nox` dobija se sljedeći ispis:
```
Booting from Hard Disk..
                       ...
[00000000] new env 00001000
                       ...
[00001000] user_mem_check assertion failure for va f010000c
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
                       ...
```
što je upravo ono što i treba da se desi.
