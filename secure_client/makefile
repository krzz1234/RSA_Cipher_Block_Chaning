secure_client.exe		: 	secure_client.o 
	g++ -Wall -O2 secure_client.cpp -lws2_32 -o secure_client.exe 
			
secure_client.o		:	secure_client.cpp 
	g++ -c -O2 -Wall secure_client.cpp
	
clean:
	del *.o
	del *.exe