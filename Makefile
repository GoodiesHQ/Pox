TARGET=pox
CC=gcc
CFLAGS=
SRC=$(TARGET).c main.c

all: pox
debug: CFLAGS += -DDEBUG
debug: pox

pox: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm $(TARGET)
