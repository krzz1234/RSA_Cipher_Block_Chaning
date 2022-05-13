//159.334 - Networks
//////////////////////
//	CLIENT GCC
/////////////////////

//Ws2_32.lib
#define _WIN32_WINNT 0x501  //to recognise getaddrinfo()


//#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <process.h>

using namespace std;

#define DEFAULT_PORT "1234" 

#define WSVERS MAKEWORD(2,2)

#define USE_IPV6 true //true

WSADATA wsadata;

enum CommandName{USER, PASS, SHUTDOWN};

/////////////////////////////////////////////////////////////////////

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


/////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {
//*******************************************************************
// Initialization
//*******************************************************************
	
	char portNum[12];
	
   SOCKET s;
   char send_buffer[9999],receive_buffer[9999],encrypt_send_buffer[9999] = "", temp[9999];
   int n,bytes;
   // Initialsing RSA keys
	static int P = 97, Q = 101;
	unsigned long long N = P*Q;
	//unsigned long long Z = (P-1)*(Q-1);
	unsigned long long E = 17;
	unsigned long long D = 1553;
	unsigned long long nonce = rand() % (N-1) + 1000; //range: from 1000 to N - 1
	unsigned long long M;

//*******************************************************************
//WSASTARTUP 
//*******************************************************************

   if (WSAStartup(WSVERS, &wsadata) != 0) {
      WSACleanup();
      printf("WSAStartup failed\n");
   	exit(1);
   } else {
		printf("\n\n===================<< CLIENT >>==================\n"); 
		printf("\nThe Winsock 2.2 dll was initialised.\n");
	}


//********************************************************************
// set the socket address structure.
//
//********************************************************************
struct addrinfo *result = NULL, hints;
int iResult;


//ZeroMemory(&hints, sizeof (hints)); //alternatively, for Windows only
memset(&hints, 0, sizeof(struct addrinfo));

if(USE_IPV6){
   hints.ai_family = AF_INET6;  
}	 else { //IPV4
   hints.ai_family = AF_INET;
}
	
hints.ai_socktype = SOCK_STREAM;
hints.ai_protocol = IPPROTO_TCP;
//hints.ai_flags = AI_PASSIVE;// PASSIVE is only for a SERVER	
	
	
	
//*******************************************************************
//	Dealing with user's arguments
//*******************************************************************
	
	//if there are 3 elements passed to the argv[] array.
   if (argc == 3){ 		
	   sprintf(portNum,"%s", argv[2]);
	   iResult = getaddrinfo(argv[1], portNum, &hints, &result);
	} else {
	   printf("USAGE: ClientWindows IP-address [port]\n"); //missing IP address
		sprintf(portNum,"%s", DEFAULT_PORT);
		printf("Default portNum = %s\n",portNum);
		printf("Using default settings, IP:127.0.0.1, Port:1234\n");
		iResult = getaddrinfo("127.0.0.1", portNum, &hints, &result);
	}
	
	if (iResult != 0) {
		 printf("getaddrinfo failed: %d\n", iResult);
		 WSACleanup();
		 return 1;
   }	 
	
//*******************************************************************
//CREATE CLIENT'S SOCKET 
//*******************************************************************
   s = INVALID_SOCKET; 	
	s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	
   if (s == INVALID_SOCKET) {
      printf("socket failed\n");
		freeaddrinfo(result);
		WSACleanup();
   	exit(1);
   }
  
	
	 if (connect(s, result->ai_addr, result->ai_addrlen) != 0) {
      printf("connect failed\n");
		freeaddrinfo(result);
		WSACleanup();
   	exit(1);
   } else {
		
		char ipver[80];
		
		// Get the pointer to the address itself, different fields in IPv4 and IPv6
		if (result->ai_family == AF_INET)
		{
			strcpy(ipver,"IPv4");
		}
		else if(result->ai_family == AF_INET6)
		{
			strcpy(ipver,"IPv6");
		}
			
		printf("\nConnected to SERVER with IP address: %s, %s at port: %s\n", argv[1], ipver,portNum);
	}

	//receives dCA
	n = 0;
	while (1){
	bytes = recv(s, &receive_buffer[n], 1, 0);
         if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
            printf("recv failed\n");
         	exit(1);
         }
         if (receive_buffer[n] == '\n') {  /*end on a LF*/
            receive_buffer[n] = '\0';
            break;
         }
         if (receive_buffer[n] != '\r') {
         	n++;   /*ignore CR's*/
         }
      }
      printf("Received Server's Certificate: PUBLIC_KEY %s\n",receive_buffer);

      //sends acknowledgment
      printf("Sending reply to SERVER: ACK 226 Public Key received\n");
      sprintf(send_buffer, "ACK 226 Public Key received\r\n");
      bytes = send(s, send_buffer, strlen(send_buffer),0);
      if (bytes == SOCKET_ERROR) {
         printf("send failed\n");
			WSACleanup();
      	exit(1);
      }
      // string tokenizer
      n = 0;
      std::string::size_type sz = 0;
      unsigned long long temp_num[2];
		char * pch;
		pch = strtok(receive_buffer," ,");
		while(pch != NULL){
			temp_num[n] =std::stoull (pch,&sz,0);
			pch = strtok(NULL, " ,");
			n++;
		}
		// Decrpyt keys
		temp_num[0] = repeatSquare(temp_num[0], D, N);
		temp_num[1] = repeatSquare(temp_num[1], D, N);
		printf("Decrypted Server's Public Key: [e = %lld, n = %lld]\n", temp_num[0], temp_num[1]);

		// Encrypt nonce
		unsigned long long en_nonce;
		en_nonce = repeatSquare(nonce, E, N);

		// Send Encrpyted nonce
		printf("Sending Nonce to SERVER: NONCE %lld\n", en_nonce);
		sprintf(send_buffer, "%lld\r\n", en_nonce);
      bytes = send(s, send_buffer, strlen(send_buffer),0);
      if (bytes == SOCKET_ERROR) {
         printf("send failed\n");
			WSACleanup();
      	exit(1);
      }

      //Recieve ACK 220
      n = 0;
		while (1){
		bytes = recv(s, &receive_buffer[n], 1, 0);
	         if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
	            printf("recv failed\n");
	         	exit(1);
	         }
	         if (receive_buffer[n] == '\n') {  /*end on a LF*/
	            receive_buffer[n] = '\0';
	            break;
	         }
	         if (receive_buffer[n] != '\r') {
	         	n++;   /*ignore CR's*/
	         }
	      }
      printf("Received packet: %s\n", receive_buffer);

		
	

	
//*******************************************************************
//Get input while user don't type "."
//*******************************************************************
	printf("\n--------------------------------------------\n");
	printf("you may now start sending commands to the SERVER.\n");
   gets(send_buffer);
   while (strcmp(send_buffer,".") != 0) {
		
      strcat(send_buffer,"\n");


//*******************************************************************
//SEND
//*******************************************************************
      //bytes = send(s, send_buffer, strlen(send_buffer),0);
		//cout << "sent " << bytes << " characters." << endl;

		if(send_buffer == NULL){
        cout << "packet is empty." << endl;
	    }
	    cout << "------------------" << endl;
	    for(unsigned int i=0; i < strlen(send_buffer); i++){
	      cout << "\tmessage[" << i << "] = " << (int)send_buffer[i] <<","<< send_buffer[i] << endl;
	      //Encrypts message
	      M = (int)send_buffer[i] ^ nonce;
	      M = repeatSquare(M, E, N);
	      sprintf(temp,"%lld ", M);
	      strcat(encrypt_send_buffer, temp);
	      nonce = M;
	    }
	    strcat(encrypt_send_buffer, "\r\n");
	    printf("<< ENCRYPT MESSAGE >> \n");
	    printf("send_buffer = %s\n", encrypt_send_buffer);
	    cout << "------------------" << endl;

	    send(s, encrypt_send_buffer, strlen(encrypt_send_buffer),0);

      if (bytes == SOCKET_ERROR) {
         printf("send failed\n");
			WSACleanup();
      	exit(1);
      }
      n = 0;
      //while (1) {
//*******************************************************************
//RECEIVE
//*******************************************************************
         /*bytes = recv(s, &receive_buffer[n], 1, 0);
         if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
            printf("recv failed\n");
         	exit(1);
         }
         if (receive_buffer[n] == '\n') {  //end on a LF
            receive_buffer[n] = '\0';
            break;
         }
         if (receive_buffer[n] != '\r') n++;   //ignore CR's
      }
      printf("SERVER's reply:%s\n",receive_buffer);
		*/
	
		memset(send_buffer,0,sizeof(send_buffer));
		memset(encrypt_send_buffer,0,sizeof(encrypt_send_buffer));
      gets(send_buffer);
	
   }
	printf("\n--------------------------------------------\n");
	printf("CLIENT is shutting down...\n");
//*******************************************************************
//CLOSESOCKET   
//*******************************************************************
   closesocket(s);
	WSACleanup();
   return 0;
}

