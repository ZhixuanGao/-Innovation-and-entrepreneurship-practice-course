**SM3算法的实现与优化**

**![C:\\Users\\xushaohua\\Desktop\\山大校徽.bmp](media/ea8941e9f2565b71776c0c122fd35624.png)**

姓名：高梽轩

学号：201900460003

班级：2019级网安2班

目录

[一． SM3算法介绍 3](#sm3算法介绍)

[二． SM3算法流程 3](#sm3算法流程)

[1. 初始化 3](#初始化)

[2. 数据填充 3](#数据填充)

[3. 迭代压缩 4](#迭代压缩)

[三． 实验环境 5](#实验环境)

[四． SM3算法实现 5](#sm3算法实现)

[1. 初始化 5](#初始化-1)

[2. 数据填充 6](#数据填充-1)

[3. 消息扩展 6](#消息扩展)

[4. 压缩函数 7](#压缩函数)

[五． SM3算法优化 7](#sm3算法优化)

[1. 优化方法 7](#优化方法)

[2. 优化原理 8](#优化原理)

[3. 优化实现 8](#优化实现)

[六． 优化前后效率对比 8](#优化前后效率对比)

# SM3算法介绍

杂凑值算法也可称为摘要算法或者哈希算法。通过对数据资料的填充、分组、扩展压缩等方式计算成特定长度的数值，来作为数据指纹或者数据特征使用。常见的MD5算法长度为128bit（16字节），SHA1算法计算长度为160bit（20字节），SHA256算法计算长度256bit（32字节），SHA512算法计算长度512bit（64字节），SM3算法计算长度为256bit（32字节）。

SM3密码杂凑值算法是国家密码局公布的自研算法，是在SHA-256基础上改进实现的一种算法，其安全性和SHA-256相当，参见国家密码局2010年12月《SM3密码杂凑算法》。其分组长度为512bit，最终计算长度为256bit（32字节）。该算法于2012年发布为密码行业标准(GM/T 0004-2012)，2016年发布为国家密码杂凑算法标准(GB/T32905-2016)。

# SM3算法流程

## 初始化

需要定义8个32bit长的容器或者寄存器V[8]，初始值赋值为一个IV值。

## 数据填充

进行数据填充的目的主要是为了数据分组压缩，计算SM3哈希值的数据有可能是文件、也可能是字符串，长度大小不一。SM3是以512bit为一组来进行计算的，只要长度满512bit即可进行一次压缩计算，到最后剩余字符不足512bit部分就需要进行填充。

假设消息m的长度为l比特。数据填充的具体步骤如下：

1.  首先将比特“1”添加到消息的末尾。
2.  再添加k个“0”，k是满足的最小的非负整数。
3.  再添加一个64位比特串，该比特串是长度l的二进制表示。

## 迭代压缩

迭代压缩主要是针对每个分组进行的，分组大小为512bit（即64字节）的data。在迭代压缩过程中还会对data进行数据扩展，既填充到不同的32bit的临时变量中，然后通过异或、循环左移等操作进行数据计算，最终更新到V[8]中。每一个分组计算完成之后，都会更新V[8]。等最后一个填充分组也进行迭代压缩之后，V[8]寄存器或者数组中的值就是本次数据计算的杂凑值。

1.  **消息扩展**

将消息分组按以下方法扩展成132个字，用于压缩函数CF：

1.  将消息分组划分为16个字。
2.  *FOR j=16 to 67:*
3.  *FOR j=0 to 63：*
    1.  **压缩函数**

令A,B,C,D,E,F,G,H为字寄存器，SS1,SS2,TT1,TT2为中间变量，压缩函数为。计算过程如下：

*FOR j=0 to 63:*

1.  **迭代过程**
2.  将填充后的消息m按512比特进行分组：，其中*n=(l+k+65)/512*。
3.  对m按下列方式迭代：

*FOR i=0 to n-1:*

其中CF是压缩函数，位256比特初始值IV，位填充后的消息分组，迭代压缩结果位。

# 实验环境

| 语言  | 系统      | 平台   | 处理器                     |
|-------|-----------|--------|----------------------------|
| C语言 | Windows10 | VS2019 | Intel(R) Core(TM) i7-9750H |

# SM3算法实现

## 初始化

| void SM3_INIT(SM3::sm3_context_s \*context) {  context-\>iv[0] = 0x7380166f;  context-\>iv[1] = 0x4914b2b9;  context-\>iv[2] = 0x172442d7;  context-\>iv[3] = 0xda8a0600;  context-\>iv[4] = 0xa96f30bc;  context-\>iv[5] = 0x163138aa;  context-\>iv[6] = 0xe38dee4d;  context-\>iv[7] = 0xb0fb0e4e; } |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 数据填充

| *//填充消息分组*  len = MessageLen \* 8;  if (IsLittleEndian())  ReverseWord(&len);  memcpy(context.MessageBlock, message + i \* 64, r);  context.MessageBlock[r] = 0x88;*//在末尾添加0x88，即0x10001000*  if (r \<= 55)*//如果剩下的位数少于440*  {  memset(context.MessageBlock + r + 1, 0, 64 - r - 1 - 8 + 4);  memcpy(context.MessageBlock + 64 - 4, \&len, 4);  SM3_ProcessMessageBlock(&context);  }  else  {  memset(context.MessageBlock + r + 1, 0, 64 - r - 1);  SM3_ProcessMessageBlock(&context);  memset(context.MessageBlock, 0, 64 - 4);  memcpy(context.MessageBlock + 64 - 4, \&len, 4);  SM3_ProcessMessageBlock(&context);  } |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 消息扩展

|  for (i = 0; i \< 16; i++)  {  W1[i] = \*(unsigned int \*)(context-\>MessageBlock + i \* 4);  if (IsLittleEndian())  ReverseWord(W1 + i);  }  for (i = 16; i \< 68; i++)  {  W1[i] = (W1[i - 16] \^ W1[i - 9] \^ LeftShift(W1[i - 3], 15)) \^ LeftShift((W1[i - 16] \^ W1[i - 9] \^ LeftShift(W1[i - 3], 15)), 15) \^ LeftShift((W1[i - 16] \^ W1[i - 9] \^ LeftShift(W1[i - 3], 15)), 23) \^ LeftShift(W1[i - 13], 7) \^ W1[i - 6];  }  for (i = 0; i \< 64; i++)  {  W2[i] = W1[i] \^ W1[i + 4];  } |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 压缩函数

| for (i = 0; i \< 64; i++)  {   SS1 = LeftShift((LeftShift(A, 12) + E + LeftShift(T(i), i)), 7);  SS2 = SS1 \^ LeftShift(A, 12);  TT1 = FF(A, B, C, i) + D + SS2 + W2[i];  TT2 = GG(E, F, G, i) + H + SS1 + W1[i];   D = C;  C = LeftShift(B, 9);  B = A;  A = TT1;  H = G;  G = LeftShift(F, 19);  F = E;  E = TT2 \^ LeftShift(TT2, 9) \^ LeftShift(TT2, 17);  } |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# SM3算法优化

## 优化方法

预计算64个常量并存储。

## 优化原理

优化后可以避免每个消息分组都去进行常数的移位操作，且优化后占用的存储空间也很少，仅256字节。

## 优化实现

| *//提前计算要使用的T常量* void calT() {  for (int i = 0; i \< 64; i++) {  t[i] = LeftShift(T(i),i);  }  return ; } |
|--------------------------------------------------------------------------------------------------------------------|

# 优化前后效率对比

实验前，我提前生成了一个文件test.txt，用来存放明文消息，大小为512KB。实验中，算法会对test.txt中存储的消息计算摘要。

优化前的运算结果如图所示。

![IMG_256](media/872409ca516689685330091245cce5cd.png)

优化后的运算结果如图所示。

![IMG_256](media/b183aedf893ef2bbe05a3fe84b35405b.png)

优化之后，运算速度有所提升。并且优化方法只需要额外的256字节的存储空间，用很小的存储代价换取了很大的性能提升。之后，我又实验了算法对不同长度的消息的加密速度，结果如下表所示。

| 文件大小   | 2MB    | 4MB    | 8MB    | 16MB    | 32MB    | 64MB    |
|------------|--------|--------|--------|---------|---------|---------|
| 优化前(ms) | 21.719 | 40.502 | 85.875 | 165.171 | 322.409 | 655.286 |
| 优化后(ms) | 13.519 | 27.264 | 55.389 | 111.557 | 213.524 | 448.274 |

从表中可以看出，运算时间几乎是和消息大小成正比的，消息越大，优化效果越明显，即缩短的运算时间就越多。
