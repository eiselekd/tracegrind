rm GPATH  GTAGS
find tracegrind coregrind VEX include -type f | grep  -e '.c$\|.h$' |  gtags -i -f -
