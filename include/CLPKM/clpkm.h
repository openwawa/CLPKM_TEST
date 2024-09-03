#ifndef __CLPKM_H__
#define __CLPKM_H__
/**************************************************************************
 * 功能：无证书公钥机制的基本功能抽象接口类CLPKM,该类被KGC和DEV继承实例化
 *   3W：240506 交子 wwj
 *
***************************************************************************/
#include <gmssl/hkdf.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <CLPKM/big.h>
#include <CLPKM/epoint.h>
#include <string>
#include <iostream>
#include <vector>
#define CLPKM_DEBUG_PRINT	1		//无证书运算开启打印调试
#define CLPKM_VERIFY_MODE	1		//国标文档参数验证模式
#if CLPKM_DEBUG_PRINT
	#define sm2_print_bn(label,a) sm2_bn_print(stderr,0,0,label,a) 
#endif

class CLPKM_COM {
private:
	std::string ID;					//设备名称
	Big priKey;						//设备的私钥
	Epoint pubKey;					//设备的公钥
	
	Big mPriKey;					//主公钥和主私钥
	Epoint mPubKey;
	Big DAi;						//随机大数，参与设备公私钥对的生成
	Epoint kgcPubKey;				//加密主公钥

	bool isKgc;						//是否为KGC标志位
	bool isGetKgcPubKey;			//是否已经获取加密主公钥标志位
	bool isGenKeyPair;
public:
	CLPKM_COM(std::string& id);		//DEV构造
	CLPKM_COM(std::string& id, const SM2_BN mpri);	//KGC构造
	virtual ~CLPKM_COM() = default;
	int setKgcPubKey(Epoint& mpubkey) { kgcPubKey = mpubkey; isGetKgcPubKey = true; return 0; }
	int setKeyPair(Big& DA, Epoint& WA) { priKey = DA; pubKey = WA; isGenKeyPair = true; return 0; }
	SM2_KEY getKeyPair(void) { SM2_KEY pair; priKey.toBytes(pair.private_key); pair.public_key = pubKey.getPoint();return pair; }
    int regenDAi(void);
    int genUA(Epoint& UA);
    int genDA(Big& TA, Big& DA);
    int verifyKeyPair(void);
	//下面两个函数为KGC方法，在KGC调用有效，DEV调用报错
    Epoint getMPubKey(void){ if (!isKgc) throw std::logic_error("KGC calls only!"); return mPubKey; }
	int genWA_TA(std::string& IDA, Epoint& UA, Epoint& WA, Big& TA);

    /*无证书生成签名和验签相关方法*/
    int genSign(std::string& msg, SM2_SIGNATURE& sig);
    int verifySign(std::string& IDA, std::string& msg, Epoint& WA, SM2_SIGNATURE& sig);

    /*国密SM2进行加解密*/
    int encrypt(std::string& IDA, std::string& msg, Epoint& WA, SM2_CIPHERTEXT& encMsg);
    int decrypt(SM2_CIPHERTEXT& encMsg, std::string& decMsg);

    
private:
	int genHA(std::string& hexIDA, Big& HA);
	int genLambda(Epoint& WA, Big& HA, Big& lambda);
    int genE(std::string& msg, Epoint& WA, Big& HA, Big& E);
	int genWA(Big& w, Epoint& UA, Epoint& WA); 
	int genTA(Big& w, Big& lambda, Big& TA);

};

//C语言版本
int genSign_C(uint8_t* ID, int IDlen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey,const SM2_KEY* keyPair, SM2_SIGNATURE* sig);
int verifySign_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_SIGNATURE* sig);
int encrypt_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_CIPHERTEXT* encMsg);
int decrypt_C(SM2_CIPHERTEXT* encMsg, const SM2_KEY* keyPair, uint8_t* decMsg, int* decMsgLen);
#endif
