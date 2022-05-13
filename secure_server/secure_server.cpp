//////////////////////////////////////////////////////////////
// TCP SERVER GCC (towards IPV6 ready)
//
//
// References: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520(v=vs.85).aspx
//             http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html#daytimeServer6
//
//////////////////////////////////////////////////////////////
//Ws2_32.lib
#define _WIN32_WINNT 0x501  //to recognise getaddrinfo()

//"For historical reasons, the Windows.h header defaults to including the Winsock.h header file for Windows Sockets 1.1. The declarations in the Winsock.h header file will conflict with the declarations in the Winsock2.h header file required by Windows Sockets 2.0. The WIN32_LEAN_AND_MEAN macro prevents the Winsock.h from being included by the Windows.h header"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


//159.334 - Networks
//single threaded server
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include<time.h>

//#pragma directives offer a way for each compiler to offer machine- and operating system-specific features
// Need to link with Ws2_32.lib
//#pragma comment (lib, "Ws2_32.lib") 
#define SECRET_PASSWORD "334"

#define WSVERS MAKEWORD(2,2) /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
                             //The high-order byte specifies the minor version number; 
									  //the low-order byte specifies the major version number.

#define USE_IPV6 true //true

#define DEFAULT_PORT "1234" 

WSADATA wsadata; //Create a WSADATA object called wsadata. 

// Encrypt & Decrypt algorithm
unsigned long long repeatSquare(unsigned long long x,unsigned long long e, unsigned long long n){
	unsigned long long y = 1;
	while(e > 0){
		if((e % 2) == 0){
			x = (x*x) % n;
			e = e / 2;
		}
		else {
			y = (x*y) % n;
			e = e - 1;
		}
	}
	return y;
}

//*******************************************************************
//MAIN
//*******************************************************************
int main(int argc, char *argv[]) {
	
//********************************************************************
// INITIALIZATION of the SOCKET library
//********************************************************************
   //struct sockaddr_in clientAddress;  //IPV4
	struct sockaddr_storage clientAddress; //IPV6
	
	char clientHost[NI_MAXHOST]; 
	char clientService[NI_MAXSERV];
	
   SOCKET s,ns;
   char send_buffer[9999],receive_buffer[9999];
   int n,bytes,addrlen;
	char portNum[NI_MAXSERV];
	char username[80];
	char passwd[80];
		
   //memset(&localaddr,0,sizeof(localaddr));

// Initialsing RSA keys
	static int P = 97, Q = 101;
	unsigned long long N = P*Q;
	//unsigned long long Z = (P-1)*(Q-1);
	//unsigned long long E = 17;
	unsigned long long D = 1553;
	unsigned long long dCA_e = 51177;
	unsigned long long dCA_n = 42697;
	unsigned long long de_nonce;

//********************************************************************
// WSSTARTUP
/*	All processes (applications or DLLs) that call Winsock functions must 
	initialize the use of the Windows Sockets DLL before making other Winsock 
	functions calls. 
	This also makes certain that Winsock is supported on the system.
*/
//********************************************************************
	int err;
	
	err = WSAStartup(WSVERS, &wsadata);
   if (err != 0) {
      WSACleanup();
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
      printf("WSAStartup failed with error: %d\n", err);
		exit(1);
   }
	
//********************************************************************
/* Confirm that the WinSock DLL supports 2.2.        */
/* Note that if the DLL supports versions greater    */
/* than 2.2 in addition to 2.2, it will still return */
/* 2.2 in wVersion since that is the version we      */
/* requested.                                        */
//********************************************************************

    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        exit(1);
    }
    else{
		  printf("\n\n<<<TCP SERVER>>>\n"); 
		  printf("\nThe Winsock 2.2 dll was initialised.\n");
	 }
	 

//********************************************************************
// set the socket address structure.
//
//********************************************************************
struct addrinfo *result = NULL;
struct addrinfo hints;
int iResult;


//********************************************************************
// STEP#0 - Specify server address information and socket properties
//********************************************************************

	 
//ZeroMemory(&hints, sizeof (hints)); //alternatively, for Windows only
memset(&hints, 0, sizeof(struct addrinfo));

if(USE_IPV6){
   hints.ai_family = AF_INET6;  
}	 else { //IPV4
   hints.ai_family = AF_INET;
}	 

hints.ai_socktype = SOCK_STREAM;
hints.ai_protocol = IPPROTO_TCP;
hints.ai_flags = AI_PASSIVE; // For wildcard IP address 
                             //setting the AI_PASSIVE flag indicates the caller intends to use 
									  //the returned socket address structure in a call to the bind function. 

// Resolve the local address and port to be used by the server
if(argc==2){	 
	 iResult = getaddrinfo(NULL, argv[1], &hints, &result); //converts human-readable text strings representing hostnames or IP addresses 
	                                                        //into a dynamically allocated linked list of struct addrinfo structures
																			  //IPV4 & IPV6-compliant
	 sprintf(portNum,"%s", argv[1]);
	 printf("\nargv[1] = %s\n", argv[1]); 	
} else {
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); //converts human-readable text strings representing hostnames or IP addresses 
	                                                             //into a dynamically allocated linked list of struct addrinfo structures
																				    //IPV4 & IPV6-compliant
	 sprintf(portNum,"%s", DEFAULT_PORT);
	 printf("\nUsing DEFAULT_PORT = %s\n", portNum); 
}

if (iResult != 0) {
    printf("getaddrinfo failed: %d\n", iResult);
    WSACleanup();
    return 1;
}	 

//********************************************************************
// STEP#1 - Create welcome SOCKET
//********************************************************************

s = INVALID_SOCKET; //socket for listening
// Create a SOCKET for the server to listen for client connections

s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

//check for errors in socket allocation
if (s == INVALID_SOCKET) {
    printf("Error at socket(): %d\n", WSAGetLastError());
    freeaddrinfo(result);
    WSACleanup();
    exit(1);//return 1;
}
//********************************************************************

	
//********************************************************************
//STEP#2 - BIND the welcome socket
//********************************************************************

// bind the TCP welcome socket to the local address of the machine and port number
    iResult = bind( s, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
		 
        closesocket(s);
        WSACleanup();
        return 1;
    }
	 
	 freeaddrinfo(result); //free the memory allocated by the getaddrinfo 
	                       //function for the server's address, as it is 
	                       //no longer needed
//********************************************************************
	 
/*
   if (bind(s,(struct sockaddr *)(&localaddr),sizeof(localaddr)) == SOCKET_ERROR) {
      printf("Bind failed!\n");
   }
*/
	
//********************************************************************
//STEP#3 - LISTEN on welcome socket for any incoming connection
//********************************************************************
	if (listen( s, SOMAXCONN ) == SOCKET_ERROR ) {
     printf( "Listen failed with error: %d\n", WSAGetLastError() );
     closesocket(s);
     WSACleanup();
     exit(1);
   } else {
		printf("\n<<<SERVER>>> is listening at PORT: %s\n", portNum);
	}
	
//*******************************************************************
//INFINITE LOOP
//********************************************************************
while (1) {  //main loop
      addrlen = sizeof(clientAddress); //IPv4 & IPv6-compliant
		
//********************************************************************
//NEW SOCKET newsocket = accept
//********************************************************************
      
	   ns = INVALID_SOCKET;

		//Accept a client socket
		//ns = accept(s, NULL, NULL);

//********************************************************************	
// STEP#4 - Accept a client connection.  
//	accept() blocks the iteration, and causes the program to wait.  
//	Once an incoming client is detected, it returns a new socket ns
// exclusively for the client.  
// It also extracts the client's IP address and Port number and stores
// it in a structure.
//********************************************************************
	
	ns = accept(s,(struct sockaddr *)(&clientAddress),&addrlen); //IPV4 & IPV6-compliant
	
	if (ns == INVALID_SOCKET) {
		 printf("accept failed: %d\n", WSAGetLastError());
		 closesocket(s);
		 WSACleanup();
		 return 1;
	} else {
		printf("\nA <<<CLIENT>>> has been accepted.\n");
		
		//strcpy(clientHost,inet_ntoa(clientAddress.sin_addr)); //IPV4
		//sprintf(clientService,"%d",ntohs(clientAddress.sin_port)); //IPV4
		
		memset(clientHost, 0, sizeof(clientHost));
		memset(clientService, 0, sizeof(clientService));

      getnameinfo((struct sockaddr *)&clientAddress, addrlen,
                    clientHost, sizeof(clientHost),
                    clientService, sizeof(clientService),
                    NI_NUMERICHOST);
		
      printf("\nConnected to <<<Client>>> with IP address:%s, at Port:%s\n",clientHost, clientService);
      std::cout << "Sending packet: PUBLIC_KEY " << dCA_e << ", " << dCA_n << std::endl;

         sprintf(send_buffer, "%lld, %lld\r\n", dCA_e, dCA_n);
         bytes = send(ns, send_buffer, strlen(send_buffer), 0);
         if (bytes == SOCKET_ERROR) break;
         //receives acknowledgement
         n=0;
         while (1) {
            bytes = recv(ns, &receive_buffer[n], 1, 0);

            if ((bytes == SOCKET_ERROR) || (bytes == 0)) break;
					 
            if (receive_buffer[n] == '\n') { //end on a LF, Note: LF is equal to one character
               receive_buffer[n] = '\0';
               printf("Received packet: %s\n", receive_buffer);
               break;
            }
            if (receive_buffer[n] != '\r'){
             	n++; //ignore CRs
            }
         }
         //Receive nonce
         n=0;
         char s[9999];
         while (1) {
            bytes = recv(ns, &receive_buffer[n], 1, 0);

            if ((bytes == SOCKET_ERROR) || (bytes == 0)) break;
					 
            if (receive_buffer[n] == '\n') { //end on a LF, Note: LF is equal to one character
               receive_buffer[n] = '\0';
               printf("Received packet: NONCE %s\n", receive_buffer);
               break;
            }
            if (receive_buffer[n] != '\r'){
            	s[n] = receive_buffer[n];
             	n++; //ignore CRs
            }
         }
         //Decrypt nonce
         char * c = s;
         std::string::size_type sz = 0;
         unsigned long long nonce;
         nonce = std::stoull (c,&sz,0);
         
         de_nonce = repeatSquare(nonce, D, N);
         printf("After decryption, received nonce = %lld\n", de_nonce);

         //Send ACK 220
         printf("Sending packet: ACK 220 nonce ok\n");
         sprintf(send_buffer, "ACK 220 nonce ok\r\n");
         bytes = send(ns, send_buffer, strlen(send_buffer), 0);
         if (bytes == SOCKET_ERROR) break;
	}	

         
		
//********************************************************************		
//Communicate with the Client
//********************************************************************
		printf("\n--------------------------------------------\n");
	   printf("the <<<SERVER>>> is waiting to receive commands.\n");
		//Clear user details
		memset(username,0,80);
		memset(passwd,0,80);
      while (1) {
         n = 0;
//********************************************************************
//RECEIVE one command (delimited by \r\n)
//********************************************************************
         while (1) {
            bytes = recv(ns, &receive_buffer[n], 1, 0);

            if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
            	printf("bytes error");
            	break;
            }
					 
            if (receive_buffer[n] == '\n') { /*end on a LF, Note: LF is equal to one character*/  
               receive_buffer[n] = '\0';
               break;
            }
            if (receive_buffer[n] != '\r'){
            	//Trim off delimeters
            	//std::cout << "\tmessage[" << n << "] = " << (int)s[n] <<","<< s[n] << std::endl;
             	n++; /*ignore CRs*/
            }
         }
			
         if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
         	printf("receive error");
         	break;
         }
         sprintf(send_buffer, "The <<<Client>>> typed '%s' - There are %d bytes of information\r\n", receive_buffer, n);
//********************************************************************
//PROCESS REQUEST
//********************************************************************			
         printf("The received encrypted message was: %s\n", receive_buffer);

         // string tokenizer
	      n = 0;
	      std::string::size_type sz = 0;
	      unsigned long long temp_num[9999], C, M;
			char * pch;
			pch = strtok(receive_buffer," ");
			while(pch != NULL){
				temp_num[n] =std::stoull (pch,&sz,0);
				pch = strtok(NULL, " ");
				n++;
			}
		// Decrypt keys
			char message[9999] = "";
			char temp[9999];
			for (int i=0; i < n; i++){
				C = repeatSquare(temp_num[i], D, N);
				M = C^de_nonce;
				memset(temp,0,sizeof(temp));
				sprintf(temp, "%c", (char)M);
				strcat(message, temp);
				de_nonce = temp_num[i];
			}
			printf("After decryption, the message found is : %s\n", message);
//********************************************************************
//SEND
//********************************************************************
			bytes = send(ns, message, strlen(message), 0);
         if (bytes == SOCKET_ERROR) {
         	printf("send error");
         	break;
         }
      }
      
//********************************************************************
//CLOSE SOCKET
//********************************************************************
		int iResult = shutdown(ns, SD_SEND);
      if (iResult == SOCKET_ERROR) {
         printf("shutdown failed with error: %d\n", WSAGetLastError());
         closesocket(ns);
         WSACleanup();
         exit(1);
      }	
//***********************************************************************
      closesocket(ns);
				
		//~ strcpy(clientHost,inet_ntoa(clientAddress.sin_addr));
		//~ sprintf(clientService,"%d",ntohs(clientAddress.sin_port));
		
      printf("\ndisconnected from <<<Client>>> with IP address:%s, Port:%s\n",clientHost, clientService);
		printf("=============================================");
		
} //main loop
//***********************************************************************

	closesocket(s);
	WSACleanup(); /* call WSACleanup when done using the Winsock dll */
   
   return 0;
}


