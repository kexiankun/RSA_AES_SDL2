
#include "mynet.h" 
#include <pthread.h>

void* handle_client(void* arg) {

    TCPsocket* client_socket_ptr = (TCPsocket*)arg;
    TCPsocket client_socket = *client_socket_ptr;

      printf("�����ӿͻ���\n");

    // ���������RSA��Կ��
    RSA *rsa_keypair = NULL;
    rsa_keypair = generateRSAKeyPair();

    wchar_t* decrypted_message = NULL;
    decrypted_message = receiveAndDecryptMessage(client_socket, rsa_keypair);
    printf("���ܺ����Ϣ��%s \n", decrypted_message);




    RSA *received_public_key = NULL;
    received_public_key = receiveRSAPublicKey(client_socket);

     printf("������Ҫ���ܵ���Ϣ��");
    char message[RES_BUFFER_SIZE]={0};
    //"�����⴩����Ҷ�ķ�϶��Ͷ�°߲���Ӱ�ӣ�΢��������棬����������������ʱ��·�ͣ�ͣ�ֻ�����������ů��";
    fgets(message, sizeof(message), stdin);

    encryptMessageAndSend(client_socket, received_public_key, message);

         // ���ͻ����Ƿ�Ͽ�����
     if (checkClientDisconnect(client_socket)) {
         printf("�ͻ����ѶϿ�����\n");
     }

     //�ر��׽��ֲ��ͷ��ڴ�
    SDLNet_TCP_Close(client_socket);
    free(client_socket_ptr);
    return NULL;
}

int main() {
    SDL_Init(SDL_INIT_EVERYTHING);
    SDLNet_Init();

    // �����������׽���
    IPaddress ip;
    SDLNet_ResolveHost(&ip, NULL, PORT);
    TCPsocket server = SDLNet_TCP_Open(&ip);

    if (!server) {
        printf("�޷������������׽���: %s\n", SDLNet_GetError());
        return 1;
    }

    pthread_t tid;
    while (1) {
        TCPsocket client_socket = SDLNet_TCP_Accept(server);
        if (client_socket) {
            TCPsocket* client_socket_ptr = (TCPsocket*)malloc(sizeof(TCPsocket));
            *client_socket_ptr = client_socket;

            if (pthread_create(&tid, NULL, handle_client, client_socket_ptr) != 0) {
                fprintf(stderr, "�޷������߳�\n");
                SDLNet_TCP_Close(client_socket);
                free(client_socket_ptr);
            } else {
                printf("��ί���µ��̴߳���ͻ�������\n");
            }
        }
    }
   
    SDLNet_TCP_Close(server);
    SDLNet_Quit();
    SDL_Quit();

    return 0;
}
