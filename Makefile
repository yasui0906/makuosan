all: makuosan.c minit.c msend.c mrecv.c mexec.c common.c
	gcc -g -lssl -lpthread -o makuosan makuosan.c minit.c msend.c mrecv.c mexec.c common.c
	gcc -g -o msync msync.c

clean:
	rm -f makuosan
	rm -f msync

install:
	cp -fp makuosan /usr/local/sbin/
	cp -fp msync /usr/local/bin/
