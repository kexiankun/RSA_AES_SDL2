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
 * 通过TCP套接字接收RSA公钥。
 * 
 * @param client_socket TCP套接字用于接收RSA公钥。
 * @return RSA* 接收到的RSA公钥，如果接收失败则返回NULL。
 */
RSA *receiveRSAPublicKey(TCPsocket client_socket) {
    int pub_key_len;
    // 接收RSA公钥的长度
    if (SDLNet_TCP_Recv(client_socket, &pub_key_len, sizeof(int)) <= 0) {
        fprintf(stderr, "无法接收RSA公钥的长度\n");
        return NULL;
    }

    // 分配内存以接收RSA公钥
    unsigned char *pub_key = (unsigned char *)malloc(pub_key_len);
    if (!pub_key) {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 接收RSA公钥
    if (SDLNet_TCP_Recv(client_socket, pub_key, pub_key_len) <= 0) {
        fprintf(stderr, "无法接收RSA公钥\n");
        free(pub_key);
        return NULL;
    }


    // 将接收到的数据转换为RSA公钥
    RSA *rsa_public_key = d2i_RSAPublicKey(NULL, (const unsigned char **)&pub_key, pub_key_len);
    if (!rsa_public_key) {
        fprintf(stderr, "无法转换接收到的数据为RSA公钥\n");
        free(pub_key);
        return NULL;
    }


    // free(pub_key);
    return rsa_public_key;
}

/**
 * 生成RSA密钥对。
 * 
 * @return RSA* 生成的RSA密钥对，如果生成失败则返回NULL。
 */
RSA *generateRSAKeyPair() {
    RSA *rsa_keypair =NULL;
         rsa_keypair = RSA_new();
    if (!rsa_keypair) {
        fprintf(stderr, "无法创建RSA密钥对\n");
        return NULL;
    }

    BIGNUM *bn = BN_new();
    if (!bn) {
        fprintf(stderr, "无法创建BIGNUM\n");
        RSA_free(rsa_keypair);
        return NULL;
    }

    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa_keypair, RSA_KEY_BITS, bn, NULL) != 1) {
        fprintf(stderr, "无法生成RSA密钥对\n");
        BN_free(bn);
        RSA_free(rsa_keypair);
        return NULL;
    }

    BN_free(bn);
    return rsa_keypair;
}


/**
 * 接收加密消息并使用RSA密钥解密。
 * 
 * @param client_socket 客户端套接字
 * @param rsa_public_key RSA公钥，用于解密消息
 * @return char* 解密后的消息，如果解密失败返回NULLY
 */
wchar_t* receiveEncryptedMessage(TCPsocket client_socket,RSA *rsa_public_key) {
    
 

    int iv_len = 0;
   
    // 接收 IV 长度信息
    if (SDLNet_TCP_Recv(client_socket, &iv_len, sizeof(int)) <= 0) {
        fprintf(stderr, "无法接收 IV 长度\n");
        
        // 处理接收失败的情况

        checkClientDisconnect(client_socket);
    }
    unsigned char *received_iv = NULL;
    // 使用动态内存分配来分配足够大小的缓冲区来接收 IV 数据
                   received_iv = (unsigned char *)malloc(iv_len + 1);
    if (received_iv == NULL) {
        fprintf(stderr, "内存分配失败\n");
        // 处理内存分配失败的情况
        checkClientDisconnect(client_socket);
    }

    // 接收 IV 数据
    if (SDLNet_TCP_Recv(client_socket, received_iv, iv_len) <= 0) {
        fprintf(stderr, "无法接收 IV 数据\n");
        // 处理接收失败的情况
       checkClientDisconnect(client_socket);
        // 释放动态分配的内存
       free(received_iv);
    }

        printf("接收IV：");
    for (int i = 0; i < iv_len; ++i) {
        printf("%02x", received_iv[i]);
    }
    printf("\n");

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    int ciphertext_len = 0;

    // 接收加密消息长度信息
    if (SDLNet_TCP_Recv(client_socket, &ciphertext_len, sizeof(int)) <= 0) {
        fprintf(stderr, "无法接收加密消息长度\n");
        // 处理接收失败的情况
        checkClientDisconnect(client_socket);
    }
    unsigned char *ciphertext = NULL;
    // 使用动态内存分配来分配足够大小的缓冲区来接收加密消息
                   ciphertext = (unsigned char *)malloc(ciphertext_len + 1);
    if (ciphertext == NULL) {
        fprintf(stderr, "内存分配失败\n");
        // 处理内存分配失败的情况
        checkClientDisconnect(client_socket);
    }

    // 接收加密的消息
    if (SDLNet_TCP_Recv(client_socket, ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "无法接收加密的消息\n");
        // 处理接收失败的情况
        checkClientDisconnect(client_socket);

        // 释放动态分配的内存
        free(ciphertext);
    }
        printf("接收加密消息：");
    for (int i = 0; i < ciphertext_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    int encrypted_aes_key_len = 0;

    // 接收加密的 AES 密钥长度信息
    if (SDLNet_TCP_Recv(client_socket, &encrypted_aes_key_len, sizeof(int)) <= 0) {
        fprintf(stderr, "无法接收加密的 AES 密钥长度\n");
        // 处理接收失败的情况
        checkClientDisconnect(client_socket);
    }
    unsigned char *encrypted_aes_key = NULL;
    // 使用动态内存分配来分配足够大小的缓冲区来接收加密的 AES 密钥
                   encrypted_aes_key = (unsigned char *)malloc(encrypted_aes_key_len + 1);
    if (encrypted_aes_key == NULL) {
        fprintf(stderr, "内存分配失败\n");
        // 处理内存分配失败的情况
        checkClientDisconnect(client_socket);
    }

    // 接收加密的 AES 密钥
    if (SDLNet_TCP_Recv(client_socket, encrypted_aes_key, encrypted_aes_key_len) <= 0) {
        fprintf(stderr, "无法接收加密的 AES 密钥\n");
        // 处理接收失败的情况
        checkClientDisconnect(client_socket);

        // 释放动态分配的内存
      free(encrypted_aes_key);
    }
        printf("接收加密的 AES 密钥：");
    for (int i = 0; i < encrypted_aes_key_len; ++i) {
        printf("%02x", encrypted_aes_key[i]);
    }
    printf("\n");


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    // 使用私钥解密接收到的加密的 AES 密钥
    unsigned char decrypted_aes_key[RSA_KEY_BITS]={0};

    int decrypted_aes_key_len = 0;
        decrypted_aes_key_len = RSA_private_decrypt(encrypted_aes_key_len, encrypted_aes_key, decrypted_aes_key, rsa_public_key, RSA_PKCS1_PADDING);
    if (decrypted_aes_key_len == -1) {
        fprintf(stderr, "解密 AES 密钥失败\n");
        RSA_free(rsa_public_key);
        return NULL;
    }
    /*---------------------------------------------------------------*/
    printf("解密后的 AES 密钥：");
    for (int i = 0; i < decrypted_aes_key_len; ++i) {
        printf("%02x", decrypted_aes_key[i]);
    }
    printf("\n");
/*-----------------------------------------------------------------*/
    RSA_free(rsa_public_key);

    // 使用解密的 AES 密钥和 IV，解密接收到的加密的消息
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, decrypted_aes_key, received_iv);

    // 定义存储解密后消息的变量
    wchar_t *decrypted_message_wide = NULL;
             decrypted_message_wide = malloc((ciphertext_len + 1) * sizeof(wchar_t*));
    if (decrypted_message_wide == NULL) {
        fprintf(stderr, "内存分配失败\n");
        EVP_CIPHER_CTX_free(ctx); // 释放解密上下文
        return NULL;
    }

    int plaintext_len = 0;
    int final_len = 0;

    // 解密消息
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_message_wide, &plaintext_len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "解密消息失败\n");
        free(decrypted_message_wide); // 释放分配的内存
        EVP_CIPHER_CTX_free(ctx); // 释放解密上下文
        return NULL;
    }

    // 继续解密可能还有的剩余部分
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_message_wide + plaintext_len, &final_len) != 1) {
        fprintf(stderr, "解密消息失败\n");
        free(decrypted_message_wide); // 释放分配的内存
        EVP_CIPHER_CTX_free(ctx); // 释放解密上下文
        return NULL;
    }

    plaintext_len += final_len;
    decrypted_message_wide[plaintext_len] = L'\0'; // 添加 null 终止符

    // 释放解密上下文
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_message_wide;

}

/**
 * 以十六进制格式打印数据。
 * 
 * @param data 要打印的数据
 * @param len 数据的长度
 */
void printHex(const unsigned char *data, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * 使用 RSA 公钥加密消息，并将加密后的消息发送到套接字。
 * 
 * @param socket 套接字
 * @param rsa_pub_key RSA 公钥
 * @param message 要加密并发送的消息
 */
void encryptAndSend(TCPsocket socket,RSA *rsa_pub_key,  char *message) {

    // 生成随机的 AES 密钥和 IV
    unsigned char aes_key[AES_KEY_SIZE / 8]={0};
    RAND_bytes(aes_key, AES_KEY_SIZE / 8);

    printf("生成随机的 AES 密钥长度: %d\n",sizeof(aes_key));

    printf("生成随机的 AES 密钥：\n");
    printHex(aes_key, sizeof(aes_key));

    unsigned char iv[AES_BLOCK_SIZE / 8]={0};
    RAND_bytes(iv, AES_BLOCK_SIZE / 8); // 生成 AES 块大小对应的 IV

    int iv_len = AES_BLOCK_SIZE / 8; // IV 的长度

    // 发送 IV 长度信息
    SDLNet_TCP_Send(socket, &iv_len, sizeof(int)); // 发送 IV 长度
    printf("已发送 IV 长度: %d\n",iv_len);

    // 发送 IV 数据
    SDLNet_TCP_Send(socket, iv, iv_len); // 发送 IV 数据
    printf("已发送 IV 数据\n");
    printHex(iv, iv_len);





    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    
    int ciphertext_len = strlen(message) + 1;
    unsigned char ciphertext[ciphertext_len];

    // 执行加密操作，生成加密后的消息
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, strlen(message) + 1);
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    // 发送加密消息长度信息
    SDLNet_TCP_Send(socket, &ciphertext_len, sizeof(int));
    printf("已发送加密消息长度: %d\n",ciphertext_len);

    // 发送加密的消息
    SDLNet_TCP_Send(socket, ciphertext, ciphertext_len);
    printf("已发送加密的消息: \n");
    printHex(ciphertext, ciphertext_len);



    int rsa_len = RSA_size(rsa_pub_key);
    unsigned char encrypted_aes_key[4096];
    int encrypted_aes_key_len = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_aes_key, rsa_pub_key, RSA_PKCS1_PADDING);

    // 发送加密的 AES 密钥长度信息
    SDLNet_TCP_Send(socket, &encrypted_aes_key_len, sizeof(int));
    printf("已发送加密的 AES 密钥长度: %d\n",encrypted_aes_key_len);
   
    // 发送加密的 AES 密钥
    SDLNet_TCP_Send(socket, encrypted_aes_key, encrypted_aes_key_len);
      printf("已发送加密的 AES 密钥: \n");
      printHex(encrypted_aes_key, encrypted_aes_key_len);

    // 打印加密的消息
    //printf("加密的消息：");
    //printHex(ciphertext, ciphertext_len);
    // // 打印加密的 AES 密钥
    // printf("加密的AES密钥：");
    // printHex(encrypted_aes_key, encrypted_aes_key_len);
    // // 打印 IV
    // printf("IV：");
    // printHex(iv, sizeof(iv));
 
}


/*
    接收并解密客户端发送的消息

    Parameters:
        client_socket: 客户端套接字
        rsa_private_key: RSA私钥

    Returns:
        解密后的消息，使用完后需要手动释放内存

    注意：
    该函数接收客户端消息并使用提供的RSA私钥解密。
*/
wchar_t* receiveAndDecryptMessage(TCPsocket client_socket, RSA *rsa_private_key) {

    // 服务端发送公钥给客户端
    unsigned char *pub_key = NULL;

    int pub_key_len = 0;
        pub_key_len = i2d_RSAPublicKey(rsa_private_key, &pub_key);//公钥
    
    SDLNet_TCP_Send(client_socket, &pub_key_len, sizeof(int));
    SDLNet_TCP_Send(client_socket, pub_key, pub_key_len);

    //文本解密函数
    wchar_t* decrypted_message= NULL;
          decrypted_message= receiveEncryptedMessage(client_socket,rsa_private_key);
    return decrypted_message;
}


/*
    从用户输入中获取消息并使用接收到的RSA公钥加密后发送给客户端

    Parameters:
        client_socket: 客户端套接字
        received_public_key: 接收到的RSA公钥
        message: 要加密和发送的消息

    注意：
    如果接收到的公钥不为空，则使用接收到的公钥加密 message 并发送。
    如果接收公钥失败，将输出错误消息。
*/
void encryptMessageAndSend(TCPsocket client_socket, RSA *received_public_key, char *message) {
    if (received_public_key != NULL) {
        encryptAndSend(client_socket, received_public_key, message);
        RSA_free(received_public_key); // 使用完成后记得释放 RSA 公钥资源
    } else {
        fprintf(stderr, "接收RSA公钥失败\n");
    }
}



//发送退出  在客服端调用
int sendDisconnectMessage(TCPsocket client_socket) {
    const char* disconnect_message = "disconnect"; // 自定义断开连接的消息
    int message_length = strlen(disconnect_message) + 1;
    int send_result = SDLNet_TCP_Send(client_socket, disconnect_message, message_length);

    if (send_result < message_length) {
        fprintf(stderr, "无法发送断开连接的通知\n");
        return 0; // 发送失败
    }

    return 1; // 发送成功
}


//接收退出  在服务端调用

int checkClientDisconnect(TCPsocket client_socket) {
    char buffer[1024];
    int recv_result = SDLNet_TCP_Recv(client_socket, buffer, sizeof(buffer));

    if (recv_result <= 0) {
        if (recv_result == 0) {
            printf("客户端断开连接\n");
        } else {
            fprintf(stderr, "接收数据出错：%s\n", SDLNet_GetError());
        }
        return 1; // 返回 1 表示客户端已断开连接
    }

    // 检查接收到的消息是否为断开连接的消息
    if (strcmp(buffer, "disconnect") == 0) {
        printf("接收到断开连接的通知\n");
        return 1; // 返回 1 表示接收到断开连接的消息
    }

    return 0; // 返回 0 表示接收到正常消息
}
