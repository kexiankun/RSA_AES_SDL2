#include "mynet.h"

int main() {

    SDL_Init(SDL_INIT_EVERYTHING);
    SDLNet_Init();

    IPaddress ip;
    TCPsocket client_socket;

    if (SDLNet_ResolveHost(&ip, "127.0.0.1", PORT) == -1) { // 121.37.89.210
        fprintf(stderr, "�޷�����������ַ\n");
        return 1;
    }

while (1)
{
    client_socket = SDLNet_TCP_Open(&ip);
    if (!client_socket) {
        fprintf(stderr, "�޷����ӵ�������\n");
        return 1;
    }

    printf("�����ӵ�������\n");


     RSA *received_public_key =NULL;
          received_public_key = receiveRSAPublicKey(client_socket);
          
               
    printf("������Ҫ���ܵ���Ϣ��");
    char message[RES_BUFFER_SIZE] = {0};
    //"��Ӱ��涣����������������ɡ��������ظ質���ƺ���˵���޾��Ĺ��¡���������Ƭ����֮�У���������������Ļ���������";
    fgets(message, sizeof(message), stdin);


     encryptMessageAndSend(client_socket,received_public_key,message);
  


          // ���������RSA��Կ��
     RSA *rsa_keypair =NULL;
          rsa_keypair = generateRSAKeyPair();
     wchar_t* decrypted_message =NULL;
           decrypted_message = receiveAndDecryptMessage(client_socket,rsa_keypair);
     
   printf("���ܺ����Ϣ��%s \n", decrypted_message);
}



 // ���ʵ��ĵط����� sendDisconnectMessage() ����
 if (!sendDisconnectMessage(client_socket)) {
    // ������ʧ�ܵ����
 }

     // �ͷ���Դ
    // RSA_free(received_public_key); // ʹ����ɺ�ǵ��ͷ� RSA ��Կ��Դ
     SDLNet_TCP_Close(client_socket);
     
     SDLNet_Quit();
     SDL_Quit();

    return 0;
}