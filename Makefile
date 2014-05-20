CC = g++
CFLAGS = -Wall -std=c++0x  $(PNAME).cpp -o $(PNAME)
PNAME = flow

all: $(PNAME).cpp
		$(CC) $(CFLAGS)

clean: $(PNAME).cpp
		rm -f $(PNAME)
