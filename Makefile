CC=g++
CFLAGS=-Wall -Werror -Wextra -pedantic -pedantic-errors -std=c++11 -g -O2 
MY_CFLAGS=-I/usr/include -I/usr/include/openssl
LIBS=-lPocoFoundation -lPocoNet -L/usr/ssl/lib -lcrypto 

all: awsv4

awsv4: awsv4.o main.o awsv4.hpp
	$(CC) -o awsv4 main.o awsv4.o $(LIBS)

lib: awsv4.o
	$(CC) awsv4.o -shared -o libawsv4.so

awsv4.o: awsv4.cpp awsv4.hpp 
	$(CC) -fPIC $(CFLAGS) $(MY_CFLAGS) -c awsv4.cpp

main.o: main.cpp awsv4.hpp
	$(CC) $(CFLAGS) $(MY_CFLAGS) -c main.cpp

clean:
	rm -f *.o awsv4
