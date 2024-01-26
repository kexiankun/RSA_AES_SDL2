#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <SDL2/SDL.h>
#include <SDL2/SDL_net.h>


#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 256
#define RSA_KEY_BITS 2048
#define PORT 8989
#define RES_BUFFER_SIZE 4096

typedef struct {
    char *public_key;
    char *private_key;
} KeyPair;

int checkClientDisconnect(TCPsocket client_socket);
/**
 * ͨ��TCP�׽��ֽ���RSA��Կ��
 * 
 * @param client_socket TCP�׽������ڽ���RSA��Կ��
 * @return RSA* ���յ���RSA��Կ���������ʧ���򷵻�NULL��
 */
RSA *receiveRSAPublicKey(TCPsocket client_socket) {
    int pub_key_len;
    // ����RSA��Կ�ĳ���
    if (SDLNet_TCP_Recv(client_socket, &pub_key_len, sizeof(int)) <= 0) {
        fprintf(stderr, "�޷�����RSA��Կ�ĳ���\n");
        return NULL;
    }

    // �����ڴ��Խ���RSA��Կ
    unsigned char *pub_key = (unsigned char *)malloc(pub_key_len);
    if (!pub_key) {
        fprintf(stderr, "�ڴ����ʧ��\n");
        return NULL;
    }

    // ����RSA��Կ
    if (SDLNet_TCP_Recv(client_socket, pub_key, pub_key_len) <= 0) {
        fprintf(stderr, "�޷�����RSA��Կ\n");
        free(pub_key);
        return NULL;
    }


    // �����յ�������ת��ΪRSA��Կ
    RSA *rsa_public_key = d2i_RSAPublicKey(NULL, (const unsigned char **)&pub_key, pub_key_len);
    if (!rsa_public_key) {
        fprintf(stderr, "�޷�ת�����յ�������ΪRSA��Կ\n");
        free(pub_key);
        return NULL;
    }


    // free(pub_key);
    return rsa_public_key;
}

/**
 * ����RSA��Կ�ԡ�
 * 
 * @return RSA* ���ɵ�RSA��Կ�ԣ��������ʧ���򷵻�NULL��
 */
RSA *generateRSAKeyPair() {
    RSA *rsa_keypair =NULL;
         rsa_keypair = RSA_new();
    if (!rsa_keypair) {
        fprintf(stderr, "�޷�����RSA��Կ��\n");
        return NULL;
    }

    BIGNUM *bn = BN_new();
    if (!bn) {
        fprintf(stderr, "�޷�����BIGNUM\n");
        RSA_free(rsa_keypair);
        return NULL;
    }

    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa_keypair, RSA_KEY_BITS, bn, NULL) != 1) {
        fprintf(stderr, "�޷�����RSA��Կ��\n");
        BN_free(bn);
        RSA_free(rsa_keypair);
        return NULL;
    }

    BN_free(bn);
    return rsa_keypair;
}


/**
 * ���ռ�����Ϣ��ʹ��RSA��Կ���ܡ�
 * 
 * @param client_socket �ͻ����׽���
 * @param rsa_public_key RSA��Կ�����ڽ�����Ϣ
 * @return char* ���ܺ����Ϣ���������ʧ�ܷ���NULLY
 */
wchar_t* receiveEncryptedMessage(TCPsocket client_socket,RSA *rsa_public_key) {
    
 

    int iv_len = 0;
   
    // ���� IV ������Ϣ
    if (SDLNet_TCP_Recv(client_socket, &iv_len, sizeof(int)) <= 0) {
        fprintf(stderr, "�޷����� IV ����\n");
        
        // �������ʧ�ܵ����

        checkClientDisconnect(client_socket);
    }
    unsigned char *received_iv = NULL;
    // ʹ�ö�̬�ڴ�����������㹻��С�Ļ����������� IV ����
                   received_iv = (unsigned char *)malloc(iv_len + 1);
    if (received_iv == NULL) {
        fprintf(stderr, "�ڴ����ʧ��\n");
        // �����ڴ����ʧ�ܵ����
        checkClientDisconnect(client_socket);
    }

    // ���� IV ����
    if (SDLNet_TCP_Recv(client_socket, received_iv, iv_len) <= 0) {
        fprintf(stderr, "�޷����� IV ����\n");
        // �������ʧ�ܵ����
       checkClientDisconnect(client_socket);
        // �ͷŶ�̬������ڴ�
       free(received_iv);
    }

        printf("����IV��");
    for (int i = 0; i < iv_len; ++i) {
        printf("%02x", received_iv[i]);
    }
    printf("\n");

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    int ciphertext_len = 0;

    // ���ռ�����Ϣ������Ϣ
    if (SDLNet_TCP_Recv(client_socket, &ciphertext_len, sizeof(int)) <= 0) {
        fprintf(stderr, "�޷����ռ�����Ϣ����\n");
        // �������ʧ�ܵ����
        checkClientDisconnect(client_socket);
    }
    unsigned char *ciphertext = NULL;
    // ʹ�ö�̬�ڴ�����������㹻��С�Ļ����������ռ�����Ϣ
                   ciphertext = (unsigned char *)malloc(ciphertext_len + 1);
    if (ciphertext == NULL) {
        fprintf(stderr, "�ڴ����ʧ��\n");
        // �����ڴ����ʧ�ܵ����
        checkClientDisconnect(client_socket);
    }

    // ���ռ��ܵ���Ϣ
    if (SDLNet_TCP_Recv(client_socket, ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "�޷����ռ��ܵ���Ϣ\n");
        // �������ʧ�ܵ����
        checkClientDisconnect(client_socket);

        // �ͷŶ�̬������ڴ�
        free(ciphertext);
    }
        printf("���ռ�����Ϣ��");
    for (int i = 0; i < ciphertext_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    int encrypted_aes_key_len = 0;

    // ���ռ��ܵ� AES ��Կ������Ϣ
    if (SDLNet_TCP_Recv(client_socket, &encrypted_aes_key_len, sizeof(int)) <= 0) {
        fprintf(stderr, "�޷����ռ��ܵ� AES ��Կ����\n");
        // �������ʧ�ܵ����
        checkClientDisconnect(client_socket);
    }
    unsigned char *encrypted_aes_key = NULL;
    // ʹ�ö�̬�ڴ�����������㹻��С�Ļ����������ռ��ܵ� AES ��Կ
                   encrypted_aes_key = (unsigned char *)malloc(encrypted_aes_key_len + 1);
    if (encrypted_aes_key == NULL) {
        fprintf(stderr, "�ڴ����ʧ��\n");
        // �����ڴ����ʧ�ܵ����
        checkClientDisconnect(client_socket);
    }

    // ���ռ��ܵ� AES ��Կ
    if (SDLNet_TCP_Recv(client_socket, encrypted_aes_key, encrypted_aes_key_len) <= 0) {
        fprintf(stderr, "�޷����ռ��ܵ� AES ��Կ\n");
        // �������ʧ�ܵ����
        checkClientDisconnect(client_socket);

        // �ͷŶ�̬������ڴ�
      free(encrypted_aes_key);
    }
        printf("���ռ��ܵ� AES ��Կ��");
    for (int i = 0; i < encrypted_aes_key_len; ++i) {
        printf("%02x", encrypted_aes_key[i]);
    }
    printf("\n");


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    // ʹ��˽Կ���ܽ��յ��ļ��ܵ� AES ��Կ
    unsigned char decrypted_aes_key[RSA_KEY_BITS]={0};

    int decrypted_aes_key_len = 0;
        decrypted_aes_key_len = RSA_private_decrypt(encrypted_aes_key_len, encrypted_aes_key, decrypted_aes_key, rsa_public_key, RSA_PKCS1_PADDING);
    if (decrypted_aes_key_len == -1) {
        fprintf(stderr, "���� AES ��Կʧ��\n");
        RSA_free(rsa_public_key);
        return NULL;
    }
    /*---------------------------------------------------------------*/
    printf("���ܺ�� AES ��Կ��");
    for (int i = 0; i < decrypted_aes_key_len; ++i) {
        printf("%02x", decrypted_aes_key[i]);
    }
    printf("\n");
/*-----------------------------------------------------------------*/
    RSA_free(rsa_public_key);

    // ʹ�ý��ܵ� AES ��Կ�� IV�����ܽ��յ��ļ��ܵ���Ϣ
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, decrypted_aes_key, received_iv);

    // ����洢���ܺ���Ϣ�ı���
    wchar_t *decrypted_message_wide = NULL;
             decrypted_message_wide = malloc((ciphertext_len + 1) * sizeof(wchar_t*));
    if (decrypted_message_wide == NULL) {
        fprintf(stderr, "�ڴ����ʧ��\n");
        EVP_CIPHER_CTX_free(ctx); // �ͷŽ���������
        return NULL;
    }

    int plaintext_len = 0;
    int final_len = 0;

    // ������Ϣ
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_message_wide, &plaintext_len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "������Ϣʧ��\n");
        free(decrypted_message_wide); // �ͷŷ�����ڴ�
        EVP_CIPHER_CTX_free(ctx); // �ͷŽ���������
        return NULL;
    }

    // �������ܿ��ܻ��е�ʣ�ಿ��
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_message_wide + plaintext_len, &final_len) != 1) {
        fprintf(stderr, "������Ϣʧ��\n");
        free(decrypted_message_wide); // �ͷŷ�����ڴ�
        EVP_CIPHER_CTX_free(ctx); // �ͷŽ���������
        return NULL;
    }

    plaintext_len += final_len;
    decrypted_message_wide[plaintext_len] = L'\0'; // ��� null ��ֹ��

    // �ͷŽ���������
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_message_wide;

}

/**
 * ��ʮ�����Ƹ�ʽ��ӡ���ݡ�
 * 
 * @param data Ҫ��ӡ������
 * @param len ���ݵĳ���
 */
void printHex(const unsigned char *data, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * ʹ�� RSA ��Կ������Ϣ���������ܺ����Ϣ���͵��׽��֡�
 * 
 * @param socket �׽���
 * @param rsa_pub_key RSA ��Կ
 * @param message Ҫ���ܲ����͵���Ϣ
 */
void encryptAndSend(TCPsocket socket,RSA *rsa_pub_key,  char *message) {

    // ��������� AES ��Կ�� IV
    unsigned char aes_key[AES_KEY_SIZE / 8]={0};
    RAND_bytes(aes_key, AES_KEY_SIZE / 8);

    printf("��������� AES ��Կ����: %d\n",sizeof(aes_key));

    printf("��������� AES ��Կ��\n");
    printHex(aes_key, sizeof(aes_key));

    unsigned char iv[AES_BLOCK_SIZE / 8]={0};
    RAND_bytes(iv, AES_BLOCK_SIZE / 8); // ���� AES ���С��Ӧ�� IV

    int iv_len = AES_BLOCK_SIZE / 8; // IV �ĳ���

    // ���� IV ������Ϣ
    SDLNet_TCP_Send(socket, &iv_len, sizeof(int)); // ���� IV ����
    printf("�ѷ��� IV ����: %d\n",iv_len);

    // ���� IV ����
    SDLNet_TCP_Send(socket, iv, iv_len); // ���� IV ����
    printf("�ѷ��� IV ����\n");
    printHex(iv, iv_len);





    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    
    int ciphertext_len = strlen(message) + 1;
    unsigned char ciphertext[ciphertext_len];

    // ִ�м��ܲ��������ɼ��ܺ����Ϣ
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, strlen(message) + 1);
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    // ���ͼ�����Ϣ������Ϣ
    SDLNet_TCP_Send(socket, &ciphertext_len, sizeof(int));
    printf("�ѷ��ͼ�����Ϣ����: %d\n",ciphertext_len);

    // ���ͼ��ܵ���Ϣ
    SDLNet_TCP_Send(socket, ciphertext, ciphertext_len);
    printf("�ѷ��ͼ��ܵ���Ϣ: \n");
    printHex(ciphertext, ciphertext_len);



    int rsa_len = RSA_size(rsa_pub_key);
    unsigned char encrypted_aes_key[4096];
    int encrypted_aes_key_len = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_aes_key, rsa_pub_key, RSA_PKCS1_PADDING);

    // ���ͼ��ܵ� AES ��Կ������Ϣ
    SDLNet_TCP_Send(socket, &encrypted_aes_key_len, sizeof(int));
    printf("�ѷ��ͼ��ܵ� AES ��Կ����: %d\n",encrypted_aes_key_len);
   
    // ���ͼ��ܵ� AES ��Կ
    SDLNet_TCP_Send(socket, encrypted_aes_key, encrypted_aes_key_len);
      printf("�ѷ��ͼ��ܵ� AES ��Կ: \n");
      printHex(encrypted_aes_key, encrypted_aes_key_len);

    // ��ӡ���ܵ���Ϣ
    //printf("���ܵ���Ϣ��");
    //printHex(ciphertext, ciphertext_len);
    // // ��ӡ���ܵ� AES ��Կ
    // printf("���ܵ�AES��Կ��");
    // printHex(encrypted_aes_key, encrypted_aes_key_len);
    // // ��ӡ IV
    // printf("IV��");
    // printHex(iv, sizeof(iv));
 
}


/*
    ���ղ����ܿͻ��˷��͵���Ϣ

    Parameters:
        client_socket: �ͻ����׽���
        rsa_private_key: RSA˽Կ

    Returns:
        ���ܺ����Ϣ��ʹ�������Ҫ�ֶ��ͷ��ڴ�

    ע�⣺
    �ú������տͻ�����Ϣ��ʹ���ṩ��RSA˽Կ���ܡ�
*/
wchar_t* receiveAndDecryptMessage(TCPsocket client_socket, RSA *rsa_private_key) {

    // ����˷��͹�Կ���ͻ���
    unsigned char *pub_key = NULL;

    int pub_key_len = 0;
        pub_key_len = i2d_RSAPublicKey(rsa_private_key, &pub_key);//��Կ
    
    SDLNet_TCP_Send(client_socket, &pub_key_len, sizeof(int));
    SDLNet_TCP_Send(client_socket, pub_key, pub_key_len);

    //�ı����ܺ���
    wchar_t* decrypted_message= NULL;
          decrypted_message= receiveEncryptedMessage(client_socket,rsa_private_key);
    return decrypted_message;
}


/*
    ���û������л�ȡ��Ϣ��ʹ�ý��յ���RSA��Կ���ܺ��͸��ͻ���

    Parameters:
        client_socket: �ͻ����׽���
        received_public_key: ���յ���RSA��Կ
        message: Ҫ���ܺͷ��͵���Ϣ

    ע�⣺
    ������յ��Ĺ�Կ��Ϊ�գ���ʹ�ý��յ��Ĺ�Կ���� message �����͡�
    ������չ�Կʧ�ܣ������������Ϣ��
*/
void encryptMessageAndSend(TCPsocket client_socket, RSA *received_public_key, char *message) {
    if (received_public_key != NULL) {
        encryptAndSend(client_socket, received_public_key, message);
        RSA_free(received_public_key); // ʹ����ɺ�ǵ��ͷ� RSA ��Կ��Դ
    } else {
        fprintf(stderr, "����RSA��Կʧ��\n");
    }
}



//�����˳�  �ڿͷ��˵���
int sendDisconnectMessage(TCPsocket client_socket) {
    const char* disconnect_message = "disconnect"; // �Զ���Ͽ����ӵ���Ϣ
    int message_length = strlen(disconnect_message) + 1;
    int send_result = SDLNet_TCP_Send(client_socket, disconnect_message, message_length);

    if (send_result < message_length) {
        fprintf(stderr, "�޷����ͶϿ����ӵ�֪ͨ\n");
        return 0; // ����ʧ��
    }

    return 1; // ���ͳɹ�
}


//�����˳�  �ڷ���˵���

int checkClientDisconnect(TCPsocket client_socket) {
    char buffer[1024];
    int recv_result = SDLNet_TCP_Recv(client_socket, buffer, sizeof(buffer));

    if (recv_result <= 0) {
        if (recv_result == 0) {
            printf("�ͻ��˶Ͽ�����\n");
        } else {
            fprintf(stderr, "�������ݳ���%s\n", SDLNet_GetError());
        }
        return 1; // ���� 1 ��ʾ�ͻ����ѶϿ�����
    }

    // �����յ�����Ϣ�Ƿ�Ϊ�Ͽ����ӵ���Ϣ
    if (strcmp(buffer, "disconnect") == 0) {
        printf("���յ��Ͽ����ӵ�֪ͨ\n");
        return 1; // ���� 1 ��ʾ���յ��Ͽ����ӵ���Ϣ
    }

    return 0; // ���� 0 ��ʾ���յ�������Ϣ
}
