
#include "mynet.h" 
#include <pthread.h>

void* handle_client(void* arg) {

    TCPsocket* client_socket_ptr = (TCPsocket*)arg;
    TCPsocket client_socket = *client_socket_ptr;

      printf("已连接客户端\n");

    // 服务端生成RSA密钥对
    RSA *rsa_keypair = NULL;
    rsa_keypair = generateRSAKeyPair();

    wchar_t* decrypted_message = NULL;
    decrypted_message = receiveAndDecryptMessage(client_socket, rsa_keypair);
    printf("解密后的消息：%s \n", decrypted_message);




    RSA *received_public_key = NULL;
    received_public_key = receiveRSAPublicKey(client_socket);

     printf("请输入要加密的消息：");
    char message[RES_BUFFER_SIZE]={0};
    //"当阳光穿过树叶的缝隙，投下斑驳的影子；微风轻拂湖面，荡起涟漪。这个午后，时间仿佛停滞，只留下清风与温暖。";
    fgets(message, sizeof(message), stdin);

    encryptMessageAndSend(client_socket, received_public_key, message);

         // 检查客户端是否断开连接
     if (checkClientDisconnect(client_socket)) {
         printf("客户端已断开连接\n");
     }

     //关闭套接字并释放内存
    SDLNet_TCP_Close(client_socket);
    free(client_socket_ptr);
    return NULL;
}

int main() {
    SDL_Init(SDL_INIT_EVERYTHING);
    SDLNet_Init();

    // 创建服务器套接字
    IPaddress ip;
    SDLNet_ResolveHost(&ip, NULL, PORT);
    TCPsocket server = SDLNet_TCP_Open(&ip);

    if (!server) {
        printf("无法创建服务器套接字: %s\n", SDLNet_GetError());
        return 1;
    }

    pthread_t tid;
    while (1) {
        TCPsocket client_socket = SDLNet_TCP_Accept(server);
        if (client_socket) {
            TCPsocket* client_socket_ptr = (TCPsocket*)malloc(sizeof(TCPsocket));
            *client_socket_ptr = client_socket;

            if (pthread_create(&tid, NULL, handle_client, client_socket_ptr) != 0) {
                fprintf(stderr, "无法创建线程\n");
                SDLNet_TCP_Close(client_socket);
                free(client_socket_ptr);
            } else {
                printf("已委派新的线程处理客户端连接\n");
            }
        }
    }
   
    SDLNet_TCP_Close(server);
    SDLNet_Quit();
    SDL_Quit();

    return 0;
}
