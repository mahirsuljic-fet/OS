Operativni sistemi (OS)
=======================

# Sadržaj
- [Materijal za učenje](#materijal-za-ucenje)
  - [Knjige i linkovi](#knjige-i-linkovi)
  - [Materijal sa fakulteta](#FET)
  - [YouTube](#youtube)
- [Skripte i rješenja problema](#skripte-i-rješenja-problema)



# Materijal za učenje

## [Knjige i linkovi](./Literatura/)
- Knjige
  - [Principi operativnih sistema kroz analizu XV6 koda](./Literatura/Principi_operativnih_sistema_kroz_analizu_XV6_koda.pdf) 
  - [Xv6 a Simple Unix-Like Teaching Operating System](./Literatura/Xv6_a_Simple_Unix-Like_Teaching_Operating_System.pdf)   
  - [Operating System Concepts](./Literatura/Operating_System_Concepts.pdf)                          
  - [Modern Operating Systems](./Literatura/Modern_Operating_Systems.pdf)                           
- Priručnici
  - [Intel 64 and IA-32 Architectures Software Developer’s Manual - Volume 3A 2007](./Literatura/IA32_Assembly_Language_Reference_Manual_Volume_3A_2007.pdf)
  - [Intel 64 and IA-32 Architectures Software Developer’s Manual - Combined Volumes 2024](./Literatura/IA32_Assembly_Language_Reference_Manual_Volume_Combined_Volumes_2024.pdf)
  - [IA-32 Assembly Language Reference Manual](./Literatura/IA-32_Assembly_Language_Reference_Manual.pdf)           
- Eksterni linkovi za knjige (najkorisniji)
  - [*Instrukcije A-M* - Intel 64 and IA-32 Architectures Software Developer’s Manual Volume 2A - 2007](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-2A.pdf)
  - [*Instrukcije N-Z* - Intel 64 and IA-32 Architectures Software Developer’s Manual Volume 2B - 2007](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-2B.pdf)
  - [*(Otprilike) sve ostalo* - Intel 64 and IA-32 Architectures Software Developer’s Manual Volume 3A - 2007](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-3A.pdf)
- Ostali korisni linkovi
  - [OSdev wiki](https://wiki.osdev.org/)
  - [Git cheatsheet](https://education.github.com/git-cheat-sheet-education.pdf)
  - [MIT 6.828](https://pdos.csail.mit.edu/6.828/2018/overview.html)
  - [XV6 github repository](https://github.com/mit-pdos/xv6-public)
  - [Intel 80386 Reference Programmer's Manual](https://pdos.csail.mit.edu/6.828/2018/readings/i386/toc.htm)
  - [x86 instrukcije (MIT)](https://pdos.csail.mit.edu/6.828/2018/readings/i386/c17.htm)
  - [x86 instrukcije (felixcloutier)](https://www.felixcloutier.com/x86/)
  - [x86 instrukcije (c9x)](https://c9x.me/x86/)


## FET

### [Predavanja](./Predavanja)
Bilješke sa predavanja.

### [Prezentacije](./Prezentacije)
Profesorove prezentacije iz predmeta.

### [Vježbe](./Vjezbe)
Kod i primjeri sa vježbi.

### [Labs](./Lab)
Rješenja lab-ova.


## YouTube

### Kanali
- [**Core Dumped**](https://www.youtube.com/@CoreDumpped)
- [Low Byte Productions](https://www.youtube.com/@LowByteProductions)
- [Neso Academy](https://www.youtube.com/@nesoacademy)
- [Dave's Garage](https://www.youtube.com/@DavesGarage)
- [Computerphile](https://www.youtube.com/@Computerphile)
- [Low Level](https://www.youtube.com/@LowLevelTV)

### Videi

#### Lab 1
- [Boot proces](https://www.youtube.com/watch?v=KkenLT8S9Hs)

#### Lab 2
- [Virtuelna memorija](https://www.youtube.com/watch?v=A9WLYbE0p-I)

#### Lab 3
- [Procesi](https://www.youtube.com/watch?v=LDhoD4IVElk)
- [Razlika između programa i procesa](https://www.youtube.com/watch?v=7ge7u5VUSbE)
- [Prekidi, protekcija, sistemski pozivi](https://www.youtube.com/watch?v=H4SDPLiUnv4)

#### Lab 4
- ["Istovremeno" izvršavanje procesa](https://www.youtube.com/watch?v=3X93PnKRNUo)
- [IPC](https://www.youtube.com/watch?v=Y2mDwW2pMv4)



# Skripte i rješenja problema


## Okruženje

### [Skripta za instalaciju/update okruženja](./getosshell.sh)
Za pokretanje skripte koristi se komanda `. ./getosshell.sh` pri čemu je potrebno biti u direktoriji gdje se nalazi `getosshell.sh`.
Skripta automatski skine najnoviju verziju okruženja, odradi sve što je potrebno i vrati terminal u direktoriju u kojoj je i bio.

### Komanda za brisanje NIX cache
Ukoliko se skine okruženje i u nekog kraćem periodu (npr. 1 dan) izađe nova verzija okruženja neće biti moguće preuzeti novu verziju dok ne prođe taj period.
Čekanje se može zaobići brisanjem cache-a komandom `rm -rf ~/.cache/nix/`.


## Neovim

### [Skripta za kreiranje compile komandi](./make_compile_commands.sh)
Ukoliko neko koristi svoj Neovim setup moguće da se u Neovim-u prikazuje puno errora iako se JOS kompajlira.
Potrebno je samo pokrenuti ovu skriptu u direktoriji gdje se nalazi JOS nakon čega će se napraviti fajl `compile_commands.json`.
Skripta se pokreće pomoću `. ./make_compile_commands.sh`. Nakon toga bi errori trebali nestati.
Prilikom dodavanja novih fajlova (npr. kada se izvrši merge sa novim lab-om) potrebno je ponovo pokrenuti ovu skriptu.

### Problem sa automatskim include standardne biblioteke
Mnoge Neovim konfiguracije automatski uključuju headere iz standardne biblioteke .
Npr. kada se napiše `printf` i pritisne enter doda se `#include <stdio.h>` na početak fajla što će izazvati grešku pri kompajliranju.
Ovo se može isključiti tako što se LSP-u kaže da to ne radi.
Potrebno je postaviti `header-insertion=never`.
Default vrijednost je `header-insertion=iwyu`.

Ukoliko se koristi Lazy i Mason (konkretnije NvChad), u fajlu `~/.config/nvim/lua/configs/lspconfig.lua` je potrebno dodati dio koga označen ispod (između ---).
Ostali argumenti su dodani za bolju funkcionalnost.

``` lua
local on_attach = require("nvchad.configs.lspconfig").on_attach
local on_init = require("nvchad.configs.lspconfig").on_init
local capabilities = require("nvchad.configs.lspconfig").capabilities

local lspconfig = require "lspconfig"
local servers = { "html", "cssls", "clangd" }

-------------------------------------------------------
lspconfig.clangd.setup {
  cmd = {
    "clangd",
    "--clang-tidy",
    "--enable-config",
    "--background-index",
    "--cross-file-rename",
    "--all-scopes-completion",
    "--completion-style=detailed",
    "--function-arg-placeholders",
    "--header-insertion=never", -- <<<<<<<<<<<<<<<<<<<<
  },
  capabilities = capabilities,
}
-------------------------------------------------------

for _, lsp in ipairs(servers) do
  lspconfig[lsp].setup {
    on_attach = on_attach,
    on_init = on_init,
    capabilities = capabilities,
  }
end
```

Za ponovo uključivanje dodavanja headera potrebno je vratiti `header-insertion` na `iwyu`:
``` lua
              ...
lspconfig.clangd.setup {
  cmd = {
              ...
    "--header-insertion=iwyu", -- <<<<<<<<<<<<<<<<<<<<
  },
              ...
}
              ...
```

Ispod je funkcija koja vrši mijenjanje između `--header-insertion=never` i `--header-insertion=iwyu`.
Funkciju je potrebno dodati u `~/.bashrc`.
Vrijednost za `lspconfig` je putanja do fajla u kojem je dodan kod iznad, postavljena je na pomenutu putanju.
``` bash
nvimswitchinchdr ()
{
  hinever='\-\-header-insertion=never'
  hiiwyu='\-\-header-insertion=iwyu'
  lspconfig=~/.config/nvim/lua/configs/lspconfig.lua
  grepnever=$(grep $hinever $lspconfig)
  grepiwyu=$(grep $hiiwyu $lspconfig)
  if [[ $grepnever ]]; then
    sed -i -e "s/$hinever/$hiiwyu/" $lspconfig
    echo "Switched to --header-insertion=iwyu"
  elif [[ $grepiwyu ]]; then
    sed -i -e "s/$hiiwyu/$hinever/" $lspconfig
    echo "Switched to --header-insertion=never"
  else
    echo "--header-insertion flag not present"
  fi
}
```
