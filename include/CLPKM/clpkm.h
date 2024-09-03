#ifndef __CLPKM_H__
#define __CLPKM_H__
/**************************************************************************
 * ���ܣ���֤�鹫Կ���ƵĻ������ܳ���ӿ���CLPKM,���౻KGC��DEV�̳�ʵ����
 *   3W��240506 ���� wwj
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
#define CLPKM_DEBUG_PRINT	1		//��֤�����㿪����ӡ����
#define CLPKM_VERIFY_MODE	1		//�����ĵ�������֤ģʽ
#if CLPKM_DEBUG_PRINT
	#define sm2_print_bn(label,a) sm2_bn_print(stderr,0,0,label,a) 
#endif

class CLPKM_COM {
private:
	std::string ID;					//�豸����
	Big priKey;						//�豸��˽Կ
	Epoint pubKey;					//�豸�Ĺ�Կ
	
	Big mPriKey;					//����Կ����˽Կ
	Epoint mPubKey;
	Big DAi;						//��������������豸��˽Կ�Ե�����
	Epoint kgcPubKey;				//��������Կ

	bool isKgc;						//�Ƿ�ΪKGC��־λ
	bool isGetKgcPubKey;			//�Ƿ��Ѿ���ȡ��������Կ��־λ
	bool isGenKeyPair;
public:
	CLPKM_COM(std::string& id);		//DEV����
	CLPKM_COM(std::string& id, const SM2_BN mpri);	//KGC����
	virtual ~CLPKM_COM() = default;
	int setKgcPubKey(Epoint& mpubkey) { kgcPubKey = mpubkey; isGetKgcPubKey = true; return 0; }
	int setKeyPair(Big& DA, Epoint& WA) { priKey = DA; pubKey = WA; isGenKeyPair = true; return 0; }
	SM2_KEY getKeyPair(void) { SM2_KEY pair; priKey.toBytes(pair.private_key); pair.public_key = pubKey.getPoint();return pair; }
    int regenDAi(void);
    int genUA(Epoint& UA);
    int genDA(Big& TA, Big& DA);
    int verifyKeyPair(void);
	//������������ΪKGC��������KGC������Ч��DEV���ñ���
    Epoint getMPubKey(void){ if (!isKgc) throw std::logic_error("KGC calls only!"); return mPubKey; }
	int genWA_TA(std::string& IDA, Epoint& UA, Epoint& WA, Big& TA);

    /*��֤������ǩ������ǩ��ط���*/
    int genSign(std::string& msg, SM2_SIGNATURE& sig);
    int verifySign(std::string& IDA, std::string& msg, Epoint& WA, SM2_SIGNATURE& sig);

    /*����SM2���мӽ���*/
    int encrypt(std::string& IDA, std::string& msg, Epoint& WA, SM2_CIPHERTEXT& encMsg);
    int decrypt(SM2_CIPHERTEXT& encMsg, std::string& decMsg);

    
private:
	int genHA(std::string& hexIDA, Big& HA);
	int genLambda(Epoint& WA, Big& HA, Big& lambda);
    int genE(std::string& msg, Epoint& WA, Big& HA, Big& E);
	int genWA(Big& w, Epoint& UA, Epoint& WA); 
	int genTA(Big& w, Big& lambda, Big& TA);

};

//C���԰汾
int genSign_C(uint8_t* ID, int IDlen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey,const SM2_KEY* keyPair, SM2_SIGNATURE* sig);
int verifySign_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_SIGNATURE* sig);
int encrypt_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_CIPHERTEXT* encMsg);
int decrypt_C(SM2_CIPHERTEXT* encMsg, const SM2_KEY* keyPair, uint8_t* decMsg, int* decMsgLen);
#endif
