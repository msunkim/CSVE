#########################################################################################################################
# A makefile for build this implementation
# @author Myungsun Kim
# @brief  one may covert into a cmake file
# 

CC=clang++
RM=rm
CFLAGS=-std=c++11 -I/usr/local/Cellar/openssl@1.1/1.1.1i/include -D__DEBUG
LDFLAGS=-L/usr/local/Cellar/openssl@1.1/1.1.1i/lib -lntl -lm -lgmp -lcrypto
DEPS = csve.h
OBJ = csve.o test.o

%.o: %.cc 
	$(CC) -c $< $(CFLAGS)

csve: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) -rf *.o *.txt csve