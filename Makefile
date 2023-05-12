mkfs:	mkfs.o main.o
	 gcc mkfs.o main.o -lm -luuid -fno-stack-protector -o mkfs

mkfs.o:	mkfs.c
	gcc -c mkfs.c

main.o:	main.c
	gcc -c main.c

