rm GPATH  GTAGS
find taintgrind coregrind VEX include -type f | grep  -e '.c$\|.h$' |  gtags -i -f -
