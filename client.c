#include "mynet.h"

int main() {

    SDL_Init(SDL_INIT_EVERYTHING);
    SDLNet_Init();

    IPaddress ip;
    TCPsocket client_socket;

    if (SDLNet_ResolveHost(&ip, "127.0.0.1", PORT) == -1) { // 121.37.89.210
        fprintf(stderr, "无法解析主机地址\n");
        return 1;
    }

while (1)
{
    client_socket = SDLNet_TCP_Open(&ip);
    if (!client_socket) {
        fprintf(stderr, "无法连接到服务器\n");
        return 1;
    }

    printf("已连接到服务器\n");


     RSA *received_public_key =NULL;
          received_public_key = receiveRSAPublicKey(client_socket);
          
               
    printf("请输入要加密的消息：");
    char message[RES_BUFFER_SIZE] = {0};
    //"树影婆娑，呼吸着生命的旋律。鸟儿欢快地歌唱，似乎述说着无尽的故事。或许，在这片宁静之中，隐藏着无数生灵的欢愉与期许。";
    fgets(message, sizeof(message), stdin);


     encryptMessageAndSend(client_socket,received_public_key,message);
  


          // 服务端生成RSA密钥对
     RSA *rsa_keypair =NULL;
          rsa_keypair = generateRSAKeyPair();
     wchar_t* decrypted_message =NULL;
           decrypted_message = receiveAndDecryptMessage(client_socket,rsa_keypair);
     
   printf("解密后的消息：%s \n", decrypted_message);
}



 // 在适当的地方调用 sendDisconnectMessage() 函数
 if (!sendDisconnectMessage(client_socket)) {
    // 处理发送失败的情况
 }

     // 释放资源
    // RSA_free(received_public_key); // 使用完成后记得释放 RSA 公钥资源
     SDLNet_TCP_Close(client_socket);
     
     SDLNet_Quit();
     SDL_Quit();

    return 0;
}