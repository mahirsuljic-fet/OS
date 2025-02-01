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
