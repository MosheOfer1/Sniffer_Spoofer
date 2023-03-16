#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#define P 9090 //port number

int main(int argc,char *argv[]) {
  char host[16];
  if (argc != 2) //Check for correct number of arguments
  {
    printf("usage: <Host>\n");
    exit(-1);
  }
   sprintf(host,"%s",argv[1]); //save the destination address

    struct sockaddr_in dest_info; //struct for destination
    struct sockaddr_in server; //struct for server
    struct sockaddr_in client; //struct for client
    int clientlen;
    char buf[1500];

    int sockP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //create socket for listening
    int sockP1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //create socket for sending

    memset((char *) &dest_info, 0, sizeof(dest_info)); //clear the memory of dest_info
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = inet_addr(host); //set the destination address
    dest_info.sin_port = htons(P + 1);

    memset((char *) &server, 0, sizeof(server)); //clear the memory of server
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY); //listen to any address
    server.sin_port = htons(P);

    if (bind(sockP, (struct sockaddr *) &server, sizeof(server)) < 0) //bind the socket to the server
        perror("ERROR on binding");

    while (1) {
        bzero(buf, 1500); //clear the buffer
        recvfrom(sockP, buf, 1500-1, 0, 
	               (struct sockaddr *) &client, &clientlen); //receive message
        printf("%s\n", buf);
        float x = ((float)random())/((float)RAND_MAX); //random number between 0 and 1
        printf("The random number is %f\n",x);
        if (x > 0.5) //send the message with probability of 50%
        {
            int b = sendto(sockP1, buf, strlen(buf), 0,
                  (struct sockaddr *)&dest_info, sizeof(dest_info)); //send the message
            printf("%d bytes sent to port P+1\n",b);
        }
        else
        {
          printf("The packet lost\n");
        }
        
    }

    close(sockP); //close the socket
    close(sockP1);

   return 0;
}
