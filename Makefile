TARGET=pox
CC=gcc
CFLAGS=
SRC=$(TARGET).c main.c

all: pox

pox: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm $(TARGET)
