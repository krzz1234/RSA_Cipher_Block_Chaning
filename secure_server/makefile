secure_server.exe		: 	secure_server.o 
	g++ secure_server.cpp -lws2_32 -o secure_server.exe 
			
secure_server.o		:	secure_server.cpp 
	g++ -c -Wall -O2 -fconserve-space secure_server.cpp

clean:
	del *.o
	del *.exe
