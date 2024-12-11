# Physical Page Management

### Note
Također pogledati exercise 7 iz [`answers_1.md`](./answers_1.md).

## Exercise 1

### `boot_alloc`
U ovoj funkciji nova stranica se alocira na sljedeći način:
- pohrani ("zapamti") se adresa sljedeće slobodne stranice (`nextfree`) u varijablu `result` \
  `result = nextfree`
- alocirane stranice se označe kao zauzete tako što se promijeni `nextfree`, odnosno adresa sljedeće slobodne stranice \
  `nextfree += ROUNDUP(n, PGSIZE)`
- izračuna se maksimalna dozvoljena adresa koja se može alocirati \
  `const char* MAX_ADDR = (char*)(KERNBASE + npages * PGSIZE)`
- provjeri se da li je alocirano više memorije nego što je dostupno, ako jest, digni paniku \
  `if (nextfree > MAX_ADDR) panic("Out of memory!")`
- na kraju se vrati pointer na početak novo-alocirane memorije, a to je pohranjeno u `result`
  `return result`

``` c
static void*
boot_alloc(uint32_t n)
{
                            ...
  result = nextfree;
  nextfree += ROUNDUP(n, PGSIZE);

  const char* MAX_ADDR = (char*)(KERNBASE + npages * PGSIZE);

  if (nextfree > MAX_ADDR)
    panic("boot_alloc: out of memory");

  return result;
}
```

### `mem_init`
Alocira se memorija za metapodatke o stranicama.
`PageInfo` je struktura u kojoj se pohranjuju metapodaci o stranicama.
`npages` je broj slobodnih stranica.
Dakle, potrebno je alocirati dovoljno memorije za `npages` struktura tipa `PageInfo`.
Za ovu namjenu se koristi `boot_alloc`.

`pages` je globalna neinicijalizirana varijabla tipa `PageInfo*`, 
koja će se koristiti kao niz metapodatka o svim okvirima (frames, fizičke stranice).
Njena vrijednost se postavlja na adresu novo-alocirane memorije dobijene pomoću `boot_alloc`.

Nakon što se alocira memorija i dodijeli vrijednost varijabli `pages`, potrebno je cijeli niz nulirati (napraviti da je svaki bajt tog memorijskog prostora nula).
To se može uraditi pomoću `memset`, 
gdje je prvi argument adresa odakle počinje popunjavanje memorije (`pages`), 
drugi argument je vrijednost kojom će se popuniti memorija, 
a treći argument je broj bajta koji će se popuniti (veličina niza koji je prethodno alociran).

``` c
void mem_init(void)
{
                            ...
  pages = (struct PageInfo*)boot_alloc(sizeof(struct PageInfo) * npages);
  memset(pages, 0, sizeof(struct PageInfo) * npages);
                            ...
}
```

### `page_init`

```
  // The example code here marks all physical pages as free.
  // However this is not truly the case.  What memory is free?
```

| Od           | Do                | Slobodno | Opis                              |
| :----------: | :---------------: | :------: | --------------------------------- |
| `0x00000000` | `0x00000400`      | NE       | Real-mode IDT and BIOS structures |
| `0x00000400` | `0x000A0000`      | DA       | Low memory (base memory)          |
| `0x000A0000` | `0x000C0000`      | NE       | VGA                               |
| `0x000C0000` | `0x000F0000`      | NE       | 16-bit devices                    |
| `0x000F0000` | `0x00100000`      | NE       | BIOS                              |
| `0x00100000` | `first_free`      | NE       | Kernel                            |
| `first_free` | `npages * PGSIZE` | DA       | Free memory                       |

Prva stranica (do `0x00000400`) nije slobodna zbog čuvanja IDR iz real moda i BIOS struktura (`1)`). \
Zatim low memory dio memorije (također poznat kao base memory) je slobodan za korištenje (`2)`). \
Zatim slijedi tzv. IO hole (rupa u memoriji zbog mapiranja VGA, raznih uređaja i BIOS-a), koji se ne smije mapirati (`3)`). \
Zatim slijedi dio memorije gdje je kernel i do sada alocirane stranice, koje su alocirane pomoću `boot_alloc`, koje su već mapirane (`4)`). \
Na kraju, od zadnje mapirane stranice do kraja fizičke memorije je slobodno za mapiranje (`4)`).

Prva adresa posle stranica mapiranih pomoću `boot_alloc` je `first_free` i definisana je u `4)`. \
`npages` je količina fizičke memorije u stranicama, deklarisana je u [`pmap.c`](../kern/pmap.c), a vrijednost joj se dodjeljuje u funkciji `i386_detect_memory` unutar istog fajla. \
`PGSIZE` je veličina jedne stranice u bajtima, definisana u [`mmu.h`](../inc/mmu.h).

```
  //  1) Mark physical page 0 as in use.
  //     This way we preserve the real-mode IDT and BIOS structures
  //     in case we ever need them.  (Currently we don't, but...)
```

Budući da je u `mem_init` svaki element od `pages` postavljen na `0`, svaki `pp_ref` će biti `0`.
Dakle ukoliko se inkrementira `pp_ref` od `pages[0]`, time će `pp_ref` nultog elementa biti `1` i tretirati će se kao zauzet.

``` c
  ++pages[0].pp_ref;
```

```
  //  2) The rest of base memory, [PGSIZE, npages_basemem * PGSIZE)
  //     is free.
```

Svaki page do `npages_basemem` će se označiti kao slobodan tako što se doda u povezanu listu (linked list) `page_free_list` koja predstavlja listu slobodnih stranica.
Efektivno se radi `push_front`.

``` c
  for (i = 1; i < npages_basemem; ++i)
  {
    pages[i].pp_link = page_free_list;
    page_free_list = &pages[i];
  }
```



```
  //  3) Then comes the IO hole [IOPHYSMEM, EXTPHYSMEM), which must
  //     never be allocated.
```

Svaki page u dijelu memorije `[IOPHYSMEM, EXTPHYSMEM)` se označava zauzet inkrementiranjem `pp_ref` koji je asociran sa njim.

``` c
  for (i = IOPHYSMEM / PGSIZE; i < EXTPHYSMEM / PGSIZE; ++i)
    ++pages[i].pp_ref;
```



```
  //  4) Then extended memory [EXTPHYSMEM, ...).
  //     Some of it is in use, some is free. Where is the kernel
  //     in physical memory?  Which pages are already in use for
  //     page tables and other data structures?
```


Konačan kod:
``` c
void page_init(void)
{
  size_t i;

  // 1)
  ++pages[0].pp_ref;

  // 2)
  for (i = 1; i < npages_basemem; ++i)
  {
    pages[i].pp_link = page_free_list;
    page_free_list = &pages[i];
  }

  // 3)
  for (i = IOPHYSMEM / PGSIZE; i < EXTPHYSMEM / PGSIZE; ++i)
    ++pages[i].pp_ref;

  // 4)
  physaddr_t first_free = PADDR(boot_alloc(0)); // address of first free byte
  int i_ff = first_free / PGSIZE;               // index of page of first free byte

  for (i = EXTPHYSMEM / PGSIZE; i < i_ff; ++i)
    ++pages[i].pp_ref;

  for (; i < npages; ++i)
  {
    pages[i].pp_link = page_free_list;
    page_free_list = &pages[i];
  }
}
```

### `page_alloc`

Nova stranica se alocira tako što se uzme zadnja slobodna stranica sa liste slobodnih stranica.

Lista slobodnih stranica je globalna varijabla `page_free_list`, deklarisana u [`pmap.c`](../kern/pmap.c), a popunjena u funkciji `page_init`.
Predstavlja strukturu podataka jednostruko povezana lista. \
Ako je `page_free_list` jednaka `NULL`, to znači da nema više slobodnih stranica, pa time nema više slobodne memorije i nije moguće alocirati novu stranicu. \
Macro `page2kva` uzima stranicu (konkretno strukturu tipa `PageInfo`) i vraća adresu u kernel virtuelnom prostoru gdje se nalazi ta stranica.

``` c
struct PageInfo*
page_alloc(int alloc_flags)
{
  // check if out of memory
  if (page_free_list == NULL)
    return NULL;

  // get new page
  struct PageInfo* new_page = page_free_list;

  // pop page from list of free pages
  page_free_list = page_free_list->pp_link;

  new_page->pp_link = NULL;

  if (alloc_flags & ALLOC_ZERO)
    memset(page2kva(new_page), 0, PGSIZE);

  return new_page;
}
```

### `page_free`

Kako bi se stranica "oslobodila" (dealocirala), potrebno je jednostavno dodati je u listu slobodnih stranica. \
Ako polje `pp_ref` date stranice (strukture `PageInfo`) nije `0`, to znači da se stranica koristi te se ne bi smjela osloboditi. \
Ako polje `pp_link` date stranice nije `NULL` (odnosno `0`), to znači da je stranica već slobodna, pa se ne bi smjela ponovo osloboditi.

``` c
void page_free(struct PageInfo* pp)
{
  if (pp->pp_ref)
    panic("page_free: page still in use");

  if (pp->pp_link)
    panic("page_free: pp_link is not NULL");

  // push page into list of free pages
  pp->pp_link = page_free_list;
  page_free_list = pp;
}
```



# Virtual Memory

## Exercise 2

Pročitana podpoglavlja 
[5.2](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s05_02.htm), 
[6.1](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_01.htm), 
[6.2](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_02.htm), 
[6.3](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_03.htm), 
[6.4](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_04.htm), 
[6.5](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_05.htm), 
[7.1](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s07_01.htm), 
[7.2](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s07_02.htm) i 
[7.3](https://pdos.csail.mit.edu/6.828/2018/readings/i386/s07_03.htm).


## Exercise 3

Koristeći QEMU monitor mogu se uporediti fizičke i virtuelne adrese.
Komandom `xp` se ispisuju vrijednosti na fizičkoj adresi, a komandomm `x` se ispisuju komande na virtuelnoj adresi.

Kernel je u fizičkoj memoriji učitan na adresu `0x00100000`, pa pomoću `xp` se dobija:
```
(qemu) xp/4x 0x00100000
0000000000100000: 0x1badb002 0x00000000 0xe4524ffe 0x7205c766
```

Trenutno postoji mapiranje 4MB virtuelnog adresnog prostora od adrese `0x00000000` na adresu `0x00000000` u fizičkom adresnom prostoru, 
i također postoji mapiranje 4MB virtuelnog adresnog prostora od adrese `0xF0000000` (`KERNBASE`) na adresu `0x00000000` u fizičkom adresnom prostoru.
Dakle, na virtuelnim adresama `0x00100000` i `0xF0100000` bi se trebalo moći pristupiti početku kernela, što se može provjeriti pomoću komande `x`:
```
(qemu) x/4x 0x00100000
00100000: 0x1badb002 0x00000000 0xe4524ffe 0x7205c766
(qemu) x/4x 0xF0100000
f0100000: 0x1badb002 0x00000000 0xe4524ffe 0x7205c766
```

Zaista, pročitani podaci su isti kao i na fizičkoj adresi `0x00100000`.

## Question 1
**Assuming that the following JOS kernel code is correct, what type should variable `x` have, `uintptr_t` or `physaddr_t`?**
``` c
mystery_t x;
char* value = return_a_pointer();
*value = 10;
x = (mystery_t) value;
```

Pozivom funkcije `return_a_pointer()` se vraća pointer koji se spremi u `value`.
U nadrednoj liniji koda se `value` dereferencira i na mjesto gdje taj pointer pokazuje se zapisuje vrijednost `10`.
Zatim se `value` kastira i pohranjuje u `x`.

Svi pointeri u C kodu (kao npr. u ovom slučaju `value` koji je tipa `char*`) pokazuju na virtuelne adrese.
Budući da je varijabla `value` dereferencirana i tu zapisana vrijednost, to znači da je `value` validan pointer i time virtuelna adresa.
Za pohranjivanje virtuelnih adresa u JOS se koristi tip `uintptr_t`.

Dakle, `mystery_t` mora biti `uintptr_t`.


## Exercise 4

### `pgdir_walk`
Funkcija `pgdir_walk` uzima page directory (`pgdir`) i virtuelnu adresu (`va`) (kao i treći argument `create`), a vraća page table entry (`pte`).
Efektivno, ova funkcija jednostavno traži `pte` koji opisuje mapiranje virtuelne adrese `va` u virtuelnom adresnom prostoru kojeg opisuje `pgdir`.

Da bi se došlo do `pte` potrebno je indeksirati `pgdir`, što daje page directory entry (`pde`) koji sadrži fizičku adresu stranice u kojoj se nalazi page table (`pt`).
Zatim je potrebno indeksirati `pt` kako bi se došlo do željenog `pte`.

Ukoliko page table (`pt`) već postoji, moguće je odma naći `pte`.
Postojanje `pt` se može provjeriti provjeravanjem `P` bita `pde`.

Ukoliko page table ne postoji, potrebno je ili kreirati ga, ili obavijestiti caller-a da on ne postoji.
Ovu odluku diktira treći argument ove funkciju koji se naziva `create`.

Ako `create` ima vrijednost `0`, tada se samo vrati vrijednost `NULL`.

Ako `create` ima vrijednost različitu od `0`, potrebno je kreirati page table, kao i `pde` za taj page table.
Da bi se kreirao page table potrebno je alocirati jednu stranicu u kojoj će se on spremiti.
Za alociranje stranica se koristi page alokator, odnosno funkcija `page_alloc`.
Ako alociranje ne uspije, kao poruka caller-u da kreiranje page table-a nije uspjelo vraća se vrijednost `NULL`.
Ako alocitanje uspije, tada je potrebno inkrementovati broj referenci na tu novu stranicu (okvir) kao znak da se ona koristi, kao i kreirati `pde`.
`pde` se sastoji od fizičke adrese sa njim asociranog page table-a i od raznih flag-ova.
Fizička adresa page table-a se može dobiti korištenjem funkcija `page2pa`.

Konačan kod:
``` c
pte_t*
pgdir_walk(pde_t* pgdir, const void* va, int create)
{
  pte_t* pte;
  pde_t* pde = &pgdir[PDX(va)];

  // check if Page Table already exists
  if (!(*pde & PTE_P))
  {
    if (!create)
      return NULL;

    // create new cleared page for Page Table
    struct PageInfo* new_page = page_alloc(ALLOC_ZERO);

    if (!new_page)
      return NULL;

    ++new_page->pp_ref;

    // create PDE for new Page Table
    *pde = page2pa(new_page) | PTE_P | PTE_U | PTE_W;
  }

  // get pointer to Page Table in virtual address space
  pte_t* pt = KADDR(PTE_ADDR(*pde));

  // get pointer to relevant Page Table Entry in virtual address space
  pte = &pt[PTX(va)];

  return pte;
}
```

### `boot_map_region`
Funkcija `boot_map_region` mapira stranice u okvire u nekom datom opsegu.
Funkcija ima pet parametara i to:
- `pgdir` označava page directory koji će se koristiti za mapiranje
- `va` označava virtuelnu adresu prve stranice iz opsega koji se mapira \
  (poravnata na `PGSIZE`)
- `size` označava količinu memorije koja se mapira
  (poravnata na `PGSIZE`)
- `pa` označava fizičku adresu prvog okvira iz opsega u koji se vrši mapiranje
  (poravnata na `PGSIZE`)
- `perm` označava permisije (flagove) koje će imati `pte`

Mapiranje se vrši kreiranjem `pte` za svaki okvir koji se mapira.
Mapiraju se stranice od `va` do `va + size` u okvire od `pa` do `pa + size`.

Korištenjem funkcije `pgdir_walk` se dobija relevantni `pte`, pri čemu se također kreira page table ako ne postoji.

`pte` se sastoji od adrese i flagova, pa se svaki `pte` kreira na taj način, 
pri čemu je `PTE_P` flag obavezan jer označava da asocirani okvir ima mapiranje u neku stranicu.

Konačan kod:
``` c
static void
boot_map_region(pde_t* pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
  for (size_t i = 0; i <= size / PGSIZE; ++i)
  {
    // get relevant pte and create page table if it doesn't exist
    pte_t* pte = pgdir_walk(pgdir, (void*)va, 1);

    if (!pte)
      panic("boot_map_region: pgdir_walk could not produce PTE");

    // create PTE for current mapping
    *pte = pa | PTE_P | perm;

    // go to next page
    pa += PGSIZE;
    va += PGSIZE;
  }
}
```

### `page_lookup`
Funkcija `page_lookup` pronalazi okvir u koji se neka virtuelna adresa (`va`) mapira, 
pri čemu također vraća relevantni `pte` caller-u, ukoliko caller to zatraži.

Fizička adresa okvira se može dobiti iz `pte`, 
a sam okvir se dobija korištenjem funkcija `pa2page` koja uzima fizičku adresu (`pa`) i 
vraća `struct PageInfo*` za okvir u kojem se nalazi ta fizička adresa.

``` c
struct PageInfo*
page_lookup(pde_t* pgdir, void* va, pte_t** pte_store)
{
  // find page
  pte_t* pte = pgdir_walk(pgdir, va, 0);

  if (!pte)
    return NULL;

  // export pte
  if (pte_store)
    *pte_store = pte;

  // return page, returns NULL if page was not found
  return pa2page(PTE_ADDR(*pte));
}
```


### `page_remove`
Funkcija `page_remove` se koristi da se izbriše mapiranje neke virtuelne adrese `va` iz virtuelnog adresnog prostora čija mapiranja opisuje page directory `pgdir`.

Funkcija pronađe okvir u kojeg se mapira virtuelna adresa `va`, 
zatim pomoću funkcije `page_decref` dekrementuje broj referenci da taj okvir, 
"izbriše" relevantni `pte` i invalidira `TLB` pomoću funkcije `tlb_invalidate`.

``` c
void page_remove(pde_t* pgdir, void* va)
{
  struct PageInfo* page;
  pte_t* pte;

  // find page
  if ((page = page_lookup(pgdir, va, &pte)))
  {
    page_decref(page);

    if (pte)
      *pte = 0;

    tlb_invalidate(pgdir, va);
  }
}
```


### `page_insert`
Funkcija `page_insert` mapira virtuelnu adresu `va` u okvir `pp`, pri čemu relevantni `pte` ima permisije definisane parametrom `perm`.

Da bi se kreiralo mapiranje potrebno je pronaći `pte` koji će se koristiti, što se može uraditi korištenjem funkcije `pgdir_walk`.
Ukoliko se već koristi taj `pte` potrebno je izbrisati to mapiranje korištenjem funkcije `page_remove`.

Za kreiranje `pte` je potrebna fizička adresa, koja se može dobiti od okvira `pp` korištenjem funkcija `page2pa`.

Bitna stvar koju je malo teže primijetiti je da je bitno inkrementovati `pp_ref` od `pp` prije brisanja asociranog mapiranje.
Ako `pp` nije prethodno mapiran `pp_ref` mu je nula `0`, tada će `pp` u potpunosti se dealocirati (dodati u linkanu listu slobodnih okvira) 
unutar funkcije `page_remove` jer ona poziva `page_decref` koja zatim poziva `page_free` ukoliko je `pp_ref == 0`.

``` c
int page_insert(pde_t* pgdir, struct PageInfo* pp, void* va, int perm)
{
  // get relevant PTE
  pte_t* pte = pgdir_walk(pgdir, va, 1);

  if (!pte)
    return -E_NO_MEM;

  ++pp->pp_ref;

  // check if page was already mapped
  if (*pte & PTE_P)
  {
    page_remove(pgdir, va);
    tlb_invalidate(pgdir, va);
  }

  // set up new mapping
  *pte = page2pa(pp) | perm | PTE_P;

  return 0;
}
```



# Kernel Address Space

## Exercise 5

Za mapiranje nekog dijela virtuelne memorije u fizičku može se koristiti funkcija `boot_map_region`.
U sva tri slučaja se koristi `kern_pgdir` page directory.

Prvo mapiranje je svih stranica iz `pages` na virtuelnu adresu `UPAGES`.
Budući da želimo da se ovom dijelu virtuelne memorije može pristupati i iz user moda koristi se permisija `PTE_U`.
Funkcija `boot_map_region` uvijek doda flag `PTE_P`, pa se on može izostaviti u argumentu koji joj se prosljeđuje.
Ne dozvoljava se pisanje u tom dijelu virtuele memorije pa se izostavlja permisija `PRE_W`.
Svaki pointer u c predstavlja virtuelnu adresu, pa pointer `pages` je potrebno prevesti u fizičku adresu korištenjem makroa `PADDR`.
``` c
  boot_map_region(kern_pgdir, UPAGES, npages * sizeof(struct PageInfo), PADDR(pages), PTE_U);
```

Slijedi mapiranje kernel stack-a.
Ovdje je glavna razlika u permisijama.
Samo kernel smije pristupati ovom dijelu memorije, pa se izostavlja `PTE_U`,
a budući da kernel treba pisati na stack, dodaje se permisija `PTE_W`.
``` c
  boot_map_region(kern_pgdir, KSTACKTOP - KSTKSIZE, KSTKSIZE, PADDR(bootstack), PTE_W);
```

Slijedi mapiranje svih virtuelnih adresa iznad `KERNBASE` na adrese od `0x0`.
Količina memorije koju treba mapirati je razlika maksimalne adrese i `KERNBASE`.
Maksimalna adresa je `2^32-1`, odnosno binarno 32 jedinice.
Broj `-1` u drugom komplementu se zapisuje kao sve jedinice,
pa kastiranjem u `uint32_t` se efektivno dobija `2^32-1`.
Oduzimanjem dobijene vrijednosti i `KERNBASE` se dobija količina memorije koja se mapira 
što se prosljeđuje funkciji `boot_map_region` kao argument za `size`.
``` c
  boot_map_region(kern_pgdir, KERNBASE, (uint32_t)(-1) - KERNBASE, 0, PTE_W);
```


## Question 2
### What entries (rows) in the page directory have been filled in at this point? What addresses do they map and where do they point? 

Korištenjem funkcija `print_mapping_info` i `printpd` (implementirane u ***Other*** dijelu odgovora) na sljedeći način:
``` c
                                    ...
  print_mapping_info("kern_pgdir", (uintptr_t)UVPT, NPDENTRIES * 4);
  kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;
  printpd(kern_pgdir);
                                    ...
  print_mapping_info("pages", UPAGES, npages * sizeof(struct PageInfo));
  boot_map_region(kern_pgdir, UPAGES, npages * sizeof(struct PageInfo), PADDR(pages), PTE_U);
  printpd(kern_pgdir);
                                    ...
  print_mapping_info("bootstack", KSTACKTOP - KSTKSIZE, KSTKSIZE);
  boot_map_region(kern_pgdir, KSTACKTOP - KSTKSIZE, KSTKSIZE, PADDR(bootstack), PTE_W);
  printpd(kern_pgdir);
                                    ...
  print_mapping_info("0x00000000", KERNBASE, (uint32_t)(-1) - KERNBASE);
  boot_map_region(kern_pgdir, KERNBASE, (uint32_t)(-1) - KERNBASE, 0, PTE_W);
  printpd(kern_pgdir);
                                    ...
```
dobija se sljedeći ispis:
```
                              ...                              
+-----------------------------+
| kern_pgdir                  |
|-----------------------------|
| BASE           | 0xef400000 |
| SIZE (BYTES)   |       4096 |
| SIZE (PAGES)   |          1 |
| SIZE (ENTRIES) |          1 |
| BASE + SIZE    | 0xef401000 |
+-----------------------------+
+-------------------------------------------------------------+
| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |
|-------------------------------------------------------------|
|   957 | 0x0011c000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 0 | 1 |
+-------------------------------------------------------------+
                              ...                              
+-----------------------------+
| pages                       |
|-----------------------------|
| BASE           | 0xef000000 |
| SIZE (BYTES)   |     262144 |
| SIZE (PAGES)   |         64 |
| SIZE (ENTRIES) |          1 |
| BASE + SIZE    | 0xef040000 |
+-----------------------------+
+-------------------------------------------------------------+
| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |
|-------------------------------------------------------------|
|   957 | 0x0011c000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 0 | 1 |
|   956 | 0x003fd000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
+-------------------------------------------------------------+
+-----------------------------+
| bootstack                   |
|-----------------------------|
| BASE           | 0xefc00000 |
| SIZE (BYTES)   |      32768 |
| SIZE (PAGES)   |          8 |
| SIZE (ENTRIES) |          1 |
| BASE + SIZE    | 0xefc08000 |
+-----------------------------+
+-------------------------------------------------------------+
| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |
|-------------------------------------------------------------|
|   959 | 0x003fe000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
|   957 | 0x0011c000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 0 | 1 |
|   956 | 0x003fd000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
+-------------------------------------------------------------+
+-----------------------------+
| 0x00000000                  |
|-----------------------------|
| BASE           | 0xf0000000 |
| SIZE (BYTES)   |  268435455 |
| SIZE (PAGES)   |      65536 |
| SIZE (ENTRIES) |         64 |
| BASE + SIZE    | 0xffffffff |
+-----------------------------+
+-------------------------------------------------------------+
| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |
|-------------------------------------------------------------|
|  1023 | 0x003be000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
                              ...                              
|   960 | 0x003ff000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
|   959 | 0x003fe000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
|   957 | 0x0011c000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 0 | 1 |
|   956 | 0x003fd000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
+-------------------------------------------------------------+
                              ...                              
```

Par napomena:
- `ADDRESS` je fizička adresa iz PDE, pa će se ovdje ignorisati
- prikazani flagovi se odnose na PDE, tako da npr. `U` flag je uvijek setovan,
  ali to nužno ne znači da se cijeli asocirani page table može koristiti u user modu,
  nego se moraju provjeriti flagovi iz PTE
- svaki PDE se koristi za mapiranje najviše 4MB memorije,
  budući da PDE od 960 do 1023 mapiraju kontinualan blok memorije,
  razmak između njihovih base adressa će biti 4MB (0x00400000)

Iz čega se jednostavno mogu pročitati traženi podaci.

| Entry | Base Virtual Address | Points to (logically)
| :---: | :------------------: | ------------------------------------
| 1023  | 0xffc00000           | fizička memorija (zadnjih 4MB)
|  960  | 0xff800000           | fizička memorija (predzadnjih 4MB)
|  ...  |     ...              | -\|\|-
|  960  | 0xf0400000           | fizička memorija (drugih 4MB)
|  960  | 0xf0000000           | fizička memorija (prvih 4MB)
|  959  | 0xefc00000           | Kernel Stack (`bootstack`)
|  957  | 0xef400000           | Kernel Page directory (`kern_pgdir`)
|  956  | 0xef000000           | Physical Page State Array (`pages`)


## Question 3
### We have placed the kernel and user environment in the same address space. Why will user programs not be able to read or write the kernel's memory? What specific mechanisms protect the kernel memory?
Da bi user program (aplikacija) pristupio nekoj stranici, potrebno je da PDE i PTE koji opisuju mapiranje te stranice u okvir imaju `U` bit postavljen na `1`.
Trenutni mod rada procesora se određuje poljem `CPL` iz `%cs` i ima vrijednost `0` (`0b00`) ako je procesor u kernel modu, a `3` (`0b11`) ako je procesor u user modu.
Pri svakom pristupu memorije provjeravaju se permisije.
Dakle, kada se izvršava user program, procesor je u user modu (`CPL` je `3`) i pri svakom pristupu memoriji provjeravaju se `U` biti asociranih PDE i PTE.
Za stranice u kojima se nalazi kernel, njihovi PTE imaju `U` bit postavljen na `0`, tako da user programi nemaju pristup tim stranicama.


## Question 4
### What is the maximum amount of physical memory that this operating system can support? Why?
Najveća količina fizičke memorije koju ovaj operativni sistem podržava je 256MB.

U funkciji `mem_init` mapira se sva fizička memorija u virtuelni adresni prostor iznad `KERNBASE`.
`KERNBASE` je konstanta definisana u [`memlayout.h`](../inc/memlayout.h) i ima vrijednost `0xf0000000`.
Dakle, moguće je mapirati onoliko fizičke memorije koliko može stati u prostor između `0xf0000000` i `0xffffffff`.
Razlika ovih brojeva je `0x0fffffff`, odnosno 256MB.

Također vrijedi pomenuti da postoji i IO "rupa" od adresa `0x000a0000` do `0x00100000` (veličine 393216B)
gdje se mapiraju VGA display, 16-bitni uređaji, BIOS, itd. i taj dio fizičke memorije se ne može koristiti, 
pa je stvarna najveća količina memorije nešto manja od 256MB.

Ovo se može i testirati.
Programu QEMU se definisati količina fizičke memorije putem argumenta `-m` ([_source_](https://wiki.gentoo.org/wiki/QEMU/Options#RAM)).
Budući da se QEMU pokreće putem make skripte [`GNUmakefile`](../GNUmakefile), ovaj argument se može dodati unutar nje.
QEMU se pokreće pomoću targeta `qemu*` koji svi koriste `QEMUOPTS`, gdje su definisane opcije za QEMU.
Bitna linija skripte je:
``` make
QEMUOPTS += $(QEMUEXTRA)
```

Varijabla `QEMUEXTRA` ne postoji, te se može dodatno definisati.
Naravno, moguće je ručno dodati dodatne opcije, ali bolje je to uraditi pomoću ove varijable.

Definisanjem `QEMUEXTRA` iznad 256MB, na način ispod se javljaju greške pri pokretanju operativnog sistema:
``` make
QEMUEXTRA = -m 257M
```

QEMU se pokreće kao i očekivano za manje vrijednosti, pa se može zaključiti da je zaista 256MB maksimalna količina fizičke memorije koju JOS podržava.


## Question 5
### How much space overhead is there for managing memory, if we actually had the maximum amount of physical memory? How is this overhead broken down?
Za svako mapiranje putem straničenja potrebno je imati page directory i page table.
Jedan page table ima 1024 PTE, što znači da može opisati mapiranje maksimalno 1024 stranice.
Veličina jednog PTE je 64b, odnosno 4B.
Dakle, jedan page table je veličine 4B * 1024, odnosno 4kB, što je i veličina jedne stranice.
Svaki page table mora imati page directory sa kojim je asociran.
Jedan page directory ima 1024 PDE, od kojih je svaki veličine 64b i vodi račun o sa njim asociranim page table-om.
Dakle, i za svaki page directory je potrebna jedna stranica (4kB).

Ukratko, za svakih 1024 stranice je potreban jedan page table, a za svakih 1024 page table-a je potreban jedan page directory.

Pored page table-a i page directory-a, potrebno je voditi računa o slobodnim okvirima.
Za tu namjenu se koristi linkana lista struktura `struct PageInfo`.
Svaka pomenuta strauktura je veličine 8B (4B za pointer na sljedeći element liste, 2B za brojač referenci i 2B padding-a).
Dakle, za svaki okvir je potrebno 8B.

Dijeljenjem 256MB (maksimalna količina fizičke memorije, iz ***question 4***) na stranice se dobija 65536 stranice.
Za 65536 stranice je potrebno 64 page table-a.
Za 64 page table-a je potreban jedan page directory.
Broj stranica je ujedno i broj okvira, dakle potrebno je 65536 `struct PageInfo`.

Dakle, potrebno je:
- 64 page table-a (262144B)
- 1 page directory (4096B)
- 65536 `struct PageInfo` (524288B)

Ukupno to je 790528B ili 772kB. Što ujedno znači da je zapravo iskoristivo oko 255.25MB memorije.


## Question 6
### Revisit the page table setup in [`kern/entry.S`](../kern/entry.S) and [`kern/entrypgdir.c`](../kern/entrypgdir.c). Immediately after we turn on paging, `EIP` is still a low number (a little over 1MB). At what point do we transition to running at an `EIP` above `KERNBASE`? 
`%eip` se prebacuje na adresu iznad `KERNBASE` u sljedećem dijelu koda iz [`kern/entry.S`](../kern/entry.S):
``` asm
	mov	$relocated, %eax
	jmp	*%eax
relocated:
	movl	$0x0,%ebp

```
i to konkretno u liniji `jmp *%eax`.
Prva instrukcija posle nje (`movl $0x0,%ebp`) će se izvršavati sa adrese iznad `KERNBASE`.
Ovo se dešava zato jer je label `relocated` na lokaciji iznad `KERNBASE`.
Također se može primijetiti da ispred argumenta instrukcije `jmp` ima `*` koja označava long jump.

### What makes it possible for us to continue executing at a low `EIP` between when we enable paging and when we begin running at an `EIP` above `KERNBASE`? Why is this transition necessary? 
Uredu je da `%eip` bude na nižoj adresi (malo iznad 1MB) zato jer u `entry_pgdir` (page directory koji definise inicjalno mapiranje)
pored toga što je dio virtuelne memorije od `KERNBASE` do `KERNBASE + 4MB` mapiran u dio fizičke memorije od `0x0` do `4MB`,
također postoji mapiranje virtuelne memorije od `0x0` do `4MB` u taj isti dio fizičke memorije od `0x0` do `4MB`.

Da ne postoji ovo mapiranje desila bi se iznimka pri pokušaju pristupanja nemapiranoj memorji.
Ovo se može i provjeriti brisanjem pomenutog mapiranja na sljedeći način:
``` c
pde_t entry_pgdir[NPDENTRIES]
  = {
      // Map VA's [0, 4MB) to PA's [0, 4MB)
      // [0]
      // = ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P,
      // Map VA's [KERNBASE, KERNBASE+4MB) to PA's [0, 4MB)
      [KERNBASE >>
        PDXSHIFT]
      = ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P + PTE_W
    };
```

Zakomentarisano je pomenuto mapiranje, i sada ako se uključi straničenje i pokuša izvršiti sljedeća instukcija pomoću GDB dobija se greška:
```
=> 0x100025:    mov    %eax,%cr0
0x00100025 in ?? ()
=> 0x100028:    Error while running hook_stop:
Cannot access memory at address 0x100028
```

Ova tranzicija, na kod iznad `KERNBASE` je potrebna jer želimo da kernel bude u dijelu virtuelne memorije iznad `KERNBASE` i da bude u svakom virtuelnom adresnom prostoru.
Kasnije će se mapiranje virtuelne memorije od `0x0` do `4MB` na isti dio fizičke memorije ukinuti, 
pa će se kernelu moći pristupiti samo iznad `KERNBASE`, i to iz svakog virtuelnog adresnog prostora.


## Challenge 1
Aktivirana je podrška za stranice od 4MB.

Implementirana je funkcija `boot_map_region_large`.
Ova funkcija radi na isti način kao i `boot_map_region` ali implementira straničenje u jednom nivou koristeći stranice od 4MB.
Poziva se u funkciji `mem_init` na isti način kao i `boot_map_region` u **exercise 5** za dio memorije iznad `KERNBASE`.

Modifikovana je funkcija `check_va2pa` jer kao što je inicijalno implementirana nije adekvatna za provjeru mapiranja koje koristi stranice od 4MB.


## Challenge 2
Implementirane su sljedeće komande:
- `printpgdir` \
  Ispisuje sve prisutne PDE od kernel page directory u vidu tabele.
- `printpgtbl` \
  Ispisuje sve prisutne PTE od navedenog entry-a iz kernel page directory u vidu tabele. \
  Komanda prima jedan argument, i to redni broj PTE.
- `showmappings` \
  Ispisuje sve virtuelne adrese iz datog opsega, u koju se fizičku adresu mapiraju i njihove flagove. \
  Može se koristiti sa jedan ili dva argumenta. \
  Ako se koristi jedan argument tada se navodi samo jedna adresa u hex formatu. \
  Ako se koriste dva argumenta tada se navodi početna adresa opsega kao prvi argument, a krajnja kao drugi, u hex formatu.
- `setmapperm` \
  Postavlja navedeni flag iz PTE navedene virtuelne adrese na 1. \
  Komanda prima dva argumenta, prvi je virtuelna adresa u hex formatu, a drugi je ime flag-a.
  Pri tome mapiranje mora postojati (PTE za navedenu virtuelnu adresu mora biti 1) i P bit se ne može mijenjati.
- `clearmapperm`
  Ista komanda kao i `setmapperm`, ali postavlja navedeni flag na 0.
- `changemapperm`
  Ista komanda kao i `setmapperm`, ali postavlja navedeni flag na vrijednost koja se proslijedi kao treći argument.
- `setmappermall`
  Postavlja sve flagove navedene virtuelne adrese na 1.
  Pri tome mapiranje mora postojati (PTE za navedenu virtuelnu adresu mora biti 1) i P bit se ne mijenja. \
  Komanda prima samo jedan argument, i to virtuelnu adresu u hex formatu.
- `clearmappermall`
  Ista komanda kao i `setmappermall`, ali postavlja sve bite (osim P bita) na 0.
- `changemappermall`
  Ista komanda kao i `setmappermall`, ali postavlja sve bite (osim P bita) na vrijednost proslijeđenu kao treći argument.
  Treći argument je u binarnom formatu, gdje svaki bit označava jedan flag na način koji se prikazuje `help` komandom.

Definicije funkcija koje implementiraju navedene komande se mogu naći u [`pmap.c`](../kern/pmap.c) ispod komentara `Challenge 2`.



# Other

### `printpd`

Pri implementaciji funkcija iz **exercise 4** činilo mi se korisno imati funkciju koja vizuelno prikazuje page directory ili page table,
odnosno prisutne PDE i PTE, pa sam to i uradio.
Funkcija ispisuje adresu i flagove datog PDE/PTE u obliku tabele.
Kod nije pretjerano lijep, ali nema neku bitnu funkciju, pa mislim da je ovakva implementacija uredu.

Implementacija:
``` c
void printpd(pde_t* pgdir)
{
  cprintf("+-------------------------------------------------------------+\n");
  cprintf("| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |\n");
  cprintf("|-------------------------------------------------------------|\n");
  for (int i = NPDENTRIES - 1; i >= 0; --i)
    if (pgdir[i] & PTE_P)
      cprintf("|  %4d | 0x%08x | %d |  %d | %d | %d |  %d  |  %d  | %d | %d | %d |\n",
        i,
        PTE_ADDR(pgdir[i]),
        (pgdir[i] & PTE_G) != 0,
        (pgdir[i] & PTE_PS) != 0,
        (pgdir[i] & PTE_D) != 0,
        (pgdir[i] & PTE_A) != 0,
        (pgdir[i] & PTE_PCD) != 0,
        (pgdir[i] & PTE_PWT) != 0,
        (pgdir[i] & PTE_U) != 0,
        (pgdir[i] & PTE_W) != 0,
        (pgdir[i] & PTE_P) != 0);
  cprintf("+-------------------------------------------------------------+\n");
}
```

Primjer korištenja:
``` c
  printpd(kern_pgdir);
```

Primjer ispisa:
```
+-------------------------------------------------------------+
| ENTRY | ADDRESS    | G | PS | D | A | PCD | PWT | U | W | P |
|-------------------------------------------------------------|
|   957 | 0x0011a000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 0 | 1 |
|   956 | 0x003fd000 | 0 |  0 | 0 | 0 |  0  |  0  | 1 | 1 | 1 |
+-------------------------------------------------------------+
```


### `print_mapping_info`
Koristi se u ***Question 2*** za dobijanje informacija o mappiranju.
Funkcija je veoma jednostavna, da, ispis će se pokvariti ukoliko se koristi prevelik title, 
ali za ove potrebe smatram da je ovo sasvim uredu.

Implementacija:
``` c
void print_mapping_info(const char* title, uintptr_t va, size_t size_b)
{
  uintptr_t base = ROUNDDOWN(va, PTSIZE);
  size_t size_p = ROUNDUP(size_b, PGSIZE) / PGSIZE;
  size_t size_e = ROUNDUP(size_p, NPTENTRIES) / NPTENTRIES;
  cprintf("+-----------------------------+\n");
  cprintf("| %-27s |\n", title);
  cprintf("|-----------------------------|\n");
  cprintf("| BASE           | %08p |\n", base);
  cprintf("| SIZE (BYTES)   | %10d |\n", size_b);
  cprintf("| SIZE (PAGES)   | %10d |\n", size_p);
  cprintf("| SIZE (ENTRIES) | %10d |\n", size_e);
  cprintf("| BASE + SIZE    | %08p |\n", base + size_b);
  cprintf("+-----------------------------+\n");
}
```

Primjer korištenja:
``` c
print_mapping_info("pages", UPAGES, npages * sizeof(struct PageInfo));
```

Primjer ispisa:
```
+-----------------------------+
| pages                       |
|-----------------------------|
| BASE           | 0xef000000 |
| SIZE (BYTES)   |     262144 |
| SIZE (PAGES)   |         64 |
| SIZE (ENTRIES) |          1 |
| BASE + SIZE    | 0xef040000 |
+-----------------------------+
```
