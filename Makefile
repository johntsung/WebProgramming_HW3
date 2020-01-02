all: HW3.c
	gcc HW3.c -lpcap -o HW3.exe


clean:
	rm HW3.exe
