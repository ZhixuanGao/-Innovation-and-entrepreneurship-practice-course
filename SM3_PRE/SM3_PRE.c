#include <string.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <iomanip>
#include <memory>
#include <stdint.h>
#include <ctime>
#include <ratio>
#include <chrono>
#include <time.h>
#include <stdlib.h>
#include "SM3.h"

using namespace std;
unsigned int hash_all = 0; //总的消息块

#define MAXSIZE 1024 * 1024 * 512 //文件最大大小
static const int test = 1;
#define JudgeEndian() (*(char *)&test == 1) //判断字节序,不为0表示是小端字节序
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) ) //向左循环移位

//T
unsigned int T(int i)
{
	if (i >= 0 && i <= 15)
		return 0x79cc4519;
	else if (i >= 16 && i <= 63)
		return 0x7a879d8a;
	else
		return 0;
}

//FF
unsigned int FF(unsigned int a, unsigned int b, unsigned int c, int i)
{
	if (i >= 0 && i <= 15)
		return a ^ b ^ c;
	else if (i >= 16 && i <= 63)
		return (a & b) | (a & c) | (b & c);
	else
		return 0;
}

//GG
unsigned int GG(unsigned int a, unsigned int b, unsigned int c, int i)
{
	if (i >= 0 && i <= 15)
		return a ^ b ^ c;
	else if (i >= 16 && i <= 63)
		return (a & b) | (~a & c);
	else
		return 0;
}

//P0
unsigned int P0(unsigned int a)
{
	return a ^ LeftRotate(a, 9) ^ LeftRotate(a, 17);
}

//P1
unsigned int P1(unsigned int a)
{
	return a ^ LeftRotate(a, 15) ^ LeftRotate(a, 23);
}

unsigned int *ReverseWord(unsigned int *sequence)
{
	//反转四个字节的字节序
	unsigned char *byte, temp;

	byte = (unsigned char *)sequence;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return sequence;

}

/*初始化函数*/
void SM3_INIT(SM3::sm3_context_s *context) {
	context->IntermediateHash[0] = 0x7380166f;
	context->IntermediateHash[1] = 0x4914b2b9;
	context->IntermediateHash[2] = 0x172442d7;
	context->IntermediateHash[3] = 0xda8a0600;
	context->IntermediateHash[4] = 0xa96f30bc;
	context->IntermediateHash[5] = 0x163138aa;
	context->IntermediateHash[6] = 0xe38dee4d;
	context->IntermediateHash[7] = 0xb0fb0e4e;
}

/* 处理消息块*/
void SM3_ProcessMessageBlock(SM3::sm3_context_s *context)
{
	int i;
	unsigned int W1[68];
	unsigned int W2[64];
	unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

	/* 消息扩展 */
	for (i = 0; i < 16; i++)
	{
		W1[i] = *(unsigned int *)(context->MessageBlock + i * 4);
		if (JudgeEndian())
			ReverseWord(W1 + i);
	}
	for (i = 16; i < 68; i++)
	{
		W1[i] = (W1[i - 16] ^ W1[i - 9] ^ LeftRotate(W1[i - 3], 15)) ^ LeftRotate((W1[i - 16] ^ W1[i - 9] ^ LeftRotate(W1[i - 3], 15)), 15) ^ LeftRotate((W1[i - 16] ^ W1[i - 9] ^ LeftRotate(W1[i - 3], 15)), 23)
			^ LeftRotate(W1[i - 13], 7) ^ W1[i - 6];
	}
	for (i = 0; i < 64; i++)
	{
		W2[i] = W1[i] ^ W1[i + 4];
	}

	/* 消息压缩 */
	A = context->IntermediateHash[0];
	B = context->IntermediateHash[1];
	C = context->IntermediateHash[2];
	D = context->IntermediateHash[3];
	E = context->IntermediateHash[4];
	F = context->IntermediateHash[5];
	G = context->IntermediateHash[6];
	H = context->IntermediateHash[7];
	for (i = 0; i < 64; i++)
	{
		unsigned int SS3;
		SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
		SS2 = SS1 ^ LeftRotate(A, 12);
		TT1 = FF(A, B, C, i) + D + SS2 + W2[i];
		TT2 = GG(E, F, G, i) + H + SS1 + W1[i];

		D = C;
		C = LeftRotate(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = LeftRotate(F, 19);
		F = E;
		E = TT2 ^ LeftRotate(TT2, 9) ^ LeftRotate(TT2, 17);
	}
	context->IntermediateHash[0] ^= A;
	context->IntermediateHash[1] ^= B;
	context->IntermediateHash[2] ^= C;
	context->IntermediateHash[3] ^= D;
	context->IntermediateHash[4] ^= E;
	context->IntermediateHash[5] ^= F;
	context->IntermediateHash[6] ^= G;
	context->IntermediateHash[7] ^= H;
}

//Calculate函数:
unsigned char *SM3::Calculate(const unsigned char *message,
	unsigned int MessageLen, unsigned char digest[HASH_SIZE])
{
	SM3:sm3_context_s context;
	unsigned int i, r, len;

	SM3_INIT(&context);
	hash_all = MessageLen / 64 + 1;
	r = MessageLen % 64;
	if (r > 55) {
		hash_all += 1;
	}
	
	for (i = 0; i < MessageLen / 64; i++)
	{
		//对前面的消息分组进行处理
		memcpy(context.MessageBlock, message + i * 64, 64);
		SM3_ProcessMessageBlock(&context);
	}

	//填充消息分组
	len = MessageLen * 8;
	if (JudgeEndian())
		ReverseWord(&len);
	memcpy(context.MessageBlock, message + i * 64, r);
	context.MessageBlock[r] = 0x88;//在末尾添加0x80，即0x10001000
	if (r <= 55)//如果剩下的位数少于440
	{
		memset(context.MessageBlock + r + 1, 0, 64 - r - 1 - 8 + 4);
		memcpy(context.MessageBlock + 64 - 4, &len, 4);
		SM3_ProcessMessageBlock(&context);
	}
	else
	{
		memset(context.MessageBlock + r + 1, 0, 64 - r - 1);
		SM3_ProcessMessageBlock(&context);
		memset(context.MessageBlock, 0, 64 - 4);
		memcpy(context.MessageBlock + 64 - 4, &len, 4);
		SM3_ProcessMessageBlock(&context);
	}

	if (JudgeEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.IntermediateHash + i);
	memcpy(digest, context.IntermediateHash, HASH_SIZE);

	return digest; 
}

//Implement_SM3函数
std::vector<uint32_t> SM3::Implement_SM3(char *filepath)
{
	std::vector<uint32_t> hash_result(32, 0);
	std::ifstream fin;
	uint32_t filesize = 0;
	unsigned char * buffer = new unsigned char[MAXSIZE];
	unsigned char hash_output[32];
	//获取文件的大小
	struct _stat info;
	_stat(filepath, &info);
	filesize = info.st_size;

	fin.open(filepath, std::ifstream::binary);
	fin >> buffer;

	auto start = std::chrono::high_resolution_clock::now();
	SM3::Calculate(buffer, filesize, hash_output);
	auto end = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double, std::ratio<1, 1000>> diff = end - start;
	std::cout << "Time: " << diff.count() << " ms\n";

	hash_result.assign(&hash_output[0], &hash_output[32]);

	delete[]buffer;
	return hash_result;
}


//创建固定大小的txt文件
void CreatTxt(char* pathName,int length)
{
	ofstream fout(pathName);
	char char_list[] = "abcdefghijklmnopqrstuvwxyz";
	int n = 26;
	if (fout) { // 如果创建成功
		for (int i = 0; i < length; i++)
		{
			fout << char_list[rand()%n];
		}

		fout.close(); 
	}
}


int main() {
	char filepath[] = "test.txt";
	//CreatTxt(filepath, 1024*512);
	std::vector<uint32_t> hash_result;
	hash_result = SM3::Implement_SM3(filepath);
	std:cout << "Hash Result: ";
 	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
		if (((i + 1) % 4) == 0) std::cout << " ";
	}
	std::cout << std::endl;
	return 0;
}

