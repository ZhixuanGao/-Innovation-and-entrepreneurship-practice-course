#pragma once

#define HASH_SIZE 32 //初始IV值长度
namespace SM3 {
	typedef struct Context {
		unsigned int intermediateHash[HASH_SIZE / 4];
		unsigned char MessageGtoup[64]; //512位的数据组
	} SM3_Context;

	unsigned char *SM3_Calculate(const unsigned char *message,
		unsigned int messagelen, unsigned char digest[HASH_SIZE]);

	std::vector<uint32_t> call_hash_sm3(char *filepath);

	double progress();
}
