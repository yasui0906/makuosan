all: makuosan.c minit.c msend.c mrecv.c mexec.c common.c
	gcc -g -lssl -lpthread -o makuosan makuosan.c minit.c msend.c mrecv.c mexec.c common.c

clean:
	rm -f makuosan
