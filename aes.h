#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(void* buffer,int buffer_len,char* IV,char* key,int key_len);

int decrypt(void* buffer,int buffer_len,char* IV,char* key,int key_len);

void display(char* ciphertext, int len);

#endif //	AES_H
