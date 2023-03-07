all: main.o aes.o
	gcc main.o aes.o -o aes

main: main.c
	gcc -c main.c

aes: aes.c aes.h
	gcc -c aes.c

clean:
	rm -f *.o aes
