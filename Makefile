all: makuosan.c minit.c msend.c mrecv.c mexec.c common.c
	gcc -g -lssl -lpthread -o makuosan makuosan.c minit.c msend.c mrecv.c mexec.c common.c
	gcc -g -o makuo makuo.c

clean:
	rm -f makuosan

install:
	cp -fp makuosan /usr/local/sbin/
	cp -fp script/makuo /usr/local/bin/
