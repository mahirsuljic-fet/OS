# Part A
- Za šta se koristi dio memorije između `MMIOBASE` i `MMIOLIM`?
- Zašto je bilo neophodno promijeniti funkciju `page_init` i kako je promijenjena?
- Šta predstavlja `MPENTRY_ADDR`?
- Zašto je za vrijednost `MPENTRY_ADDR` izabrano `0x7000`?
- Za šta se koristi `kern/mpentry.S`?
- Kako i zašto se `kern/mpentry.S` razlikuje od `boot/boot.S`? \
  (Šta radi `boot/boot.S` što `kern/mpentry.S` ne mora?)
- Šta je BSP, a šta AP?
- Koja je razlika između BSP i AP?
- Koliko ima BSP, a koliko AP?
- Ko, kada i kako probudi AP?
- Koliko JOS ima kernel stackova? Zašto?
- Koliko XV6 ima kernel stackova? Zašto?
- Gdje se nalaze JOS kernel stackovi?
- Kako je organizovan dio memorije u kojem su kernel stackovi?
- Šta se desi ako neko jezgro popuni svoj cijeli kernel stack?
  Može taj slučaj naštetiti ostalim jezgrima?
- Zašto se više ne može koristiti globalna varijabla `ts`? \
  (`ts` je predstavljala TSS) \
  ili \
  Koliko TSS JOS ima u ovom labu? Zašto?
- Za šta služi registar `%tr`?
- Šta je spinlock i kako radi?
- Koji metod zaključavanja koristi JOS? Kako on radi?
- Šta radi scheduler?
- Koju metodu schedulinga koristi JOS? Kako ona radi? U kojoj funkciji je implementirana?
- Šta scheduler radi ako ne nađe RUNNABLE okruženje? Šta ako i to ne uspije?
- Kako jezgro nastavlja izvršavanje nakon što se zaustavi u funkciji `sched_halt`?
- Šta radi sistemski poziv `sys_exofork`?
- Koja je najviša adresa koju korisnička okruženja smiju mijenjati?
- Koja je najviša adresa koju korisnička okruženja smiju čitati?

# Part B
- Šta je i za šta se koristi `env_pgfault_upcall`?
- Koja je razlika između tretiranja page faulta u `trap` i pomoću upcall funkcije?
- Koliko stackova svako okruženje ima? Koji su to?
- Koji se stack koristi za tretiranje iznimki u user modu?
- Na koji način se tretira page fault u user modu? \
  Koji je posao kernela u tom slučaju?
- Koja je razlika pri tretiranju paga faulta koji se desio dok se koristio exception stack i "obični" stack?
- Koji je mogući način tretiranja page faulta koji se desio usljed ispunjavanja cijelog stacka okruženja?
- Šta se desi ako okruženje popuni cijeli svoj exception stack? Ko i kako tretira tu situaciju?
- Šta radi funkcija `_pgfault_upcall`?
- Kako se implementira funkcija `_pgfault_upcall`?
- Koje su poteškoće/ograničenja pri implementaciji funkcije `_pgfault_upcall`?
- U kojem modu je procesor kada se pozove `_pgfault_upcall` i koji se stack koristi? \
  Da li se koristi isti stack prije poziva, u toku poziva i posle poziva funkcije `_pgfault_upcall`?
- Šta je fork i za šta služi?
- Šta radi parent okruženje prilikom fork-a, a šta child okruženje?
- Prilikom fork-anja, šta sve parent okruženje mora uraditi nakon poziva `sys_exofork`?
- Kada se child okruženje stekne uslove da se može izvršavati, a kada se krene izvršavati?
- Kroz koja stanja child okruženje prođe prilikom fork-anja?
- Zašto je potrebno promijeniti `thisenv` u child okruženju prilikom fork-a?
- Kako je moguće znati da li je okruženje koje se izvršava parent ili child okruženje?
- Šta je copy-on-write fork?
- Koja je razlika između implementacije fork-a u JOS i XV6?
- Šta radi funkcija `duppage`?
- Gdje se nalazi oznaka za copy-on-write (`PTE_COW`)? \
  (Ne u kojem fajlu, nego u memoriji, u kojoj strukturi?) \
  Koji se biti koriste za tu namjenu?
- Koja je svrha funkcije `pgfault`, šta ona radi?
- Kada se poziva funkcija `pgfault`?
- Na koji način radi funkcija `pgfault`?

# Part C
- Šta je LAPIC?
- Koja je razlika između IRQ i prekida koji su implementirani u lab 3?
- Kako se generišu IRQ? Odakle dolaze?
- Šta je `IRQ_OFFSET` i zašto se koristi?
- Zašto je vrijednost `IRQ_OFFSET` postavljena na 32? \
  Da li je bilo moguće koristiti neku drugu vrijednost? \
  Koja je najmanja vrijednost koja bi se trebala koristiti? Zašto?
- Šta diktira da li su prekidi uključeni ili ne? \
  (Konkretno u hardveru)
- Koji su načini uključivanja/isljučivanja prekida (bar 2)?
- Šta je timer? \
  Zašto je potreban? \
  Koji su mogući problemi da timer ne postoji?
- Šta procesor treba uraditi kada završi tretiranje prekida? \
  (Vezano za LAPIC)
- Šta je IPC?
- Šta se može razmjenjivati pomoću IPC?
- Na koji način radi primanje IPC poruke? \
  Koja polja `struct Env` okruženja i kako se promijene za okruženje koje čeka poruku?
- Na koji način radi slanje IPC poruke?
- Kako okruženje označava da želi ili ne želi primati/slati stranicu?
- Na koji način se dijele stranice pomoću IPC?
- Ako dva okruženja dijele neku stranicu, da li se korištenje te stranice odvija sa pomoći kernela ili kernel više nema veze sa tim?
- Šta ako jedno okruženje šalje poruku drugom okruženju koje nije spremno da primi poruku? Šta se desi u tom slučaju? Kako je ovo implementirano?
- Kako radi program `primes`?
