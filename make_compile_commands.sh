search='"."'
replace=$(pwd | sed "s/\//\\\\\//g")
make --always-make --dry-run \
 | grep -wE 'gcc|g\+\+' \
 | grep -w '\-c' \
 | jq -nR '[inputs|{directory:".", command:., file: match(" [^ ]+$").string[1:]}]' \
 | sed 's/ -gstabs//g' \
 | sed 's/ -fno-tree-ch//g' \
 | sed "s/$search/\"$replace\"/" \
 > compile_commands.json
