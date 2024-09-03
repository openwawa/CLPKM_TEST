#include <CLPKM/clpkm.h>

const SM2_BN SM2_N = {
	0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};	//阶数
const SM2_BN testDAi = {
	0x48004C00,0x28142A18,0x04331442,0x0A02285A,
	0x44C60043,0xC3111029,0x251A59A2,0x04914C20
};
const SM2_BN testW = {
	 0x1FB2F96F,0x260DBAAE,0xDD72B727,0xC176D925,
	 0x4817663F,0x94F94E93,0x385C175C,0x6CB28D99
};
const SM2_BN SM2_A = {
	0xfffffffc, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};
const SM2_BN SM2_B = {
	0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
	0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
};
const unsigned char SM2_a[] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
const unsigned char SM2_b[] = {
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
	0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
	0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93 
};
const unsigned char SM2_xg[] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
	0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
	0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};
const unsigned char SM2_yg[] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
	0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
	0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

Big CLPKM_N, CLPKM_A, CLPKM_B;

void hexCharBuf_print(const char* name, uint8_t* src, int size) {
	printf("\n%s", name);
	for (int i = 0; i < size; i++) {
		if (i % POINT_SIZE == 0) printf("\n");
		printf("%02X", src[i]);
	}
	printf("\n");
}
void printPara(const char* name, Epoint& src) {
	uint8_t str[65];
	src.toBytes(str);
	hexCharBuf_print(name, str + 1, POINT_SIZE * 2);
}
void printPara(const char* name, Big& src) {
	uint8_t str[32];
	src.toBytes(str);
	hexCharBuf_print(name, str, POINT_SIZE);
}
int  hexCharToValue(char hex) {
	if ('0' <= hex && hex <= '9') {
		return hex - '0';
	}
	else if ('a' <= hex && hex <= 'f') {
		return 10 + (hex - 'a');
	}
	else if ('A' <= hex && hex <= 'F') {
		return 10 + (hex - 'A');
	}
	else {
		// 非法的十六进制字符
		return -1;
	}
}
void hexString_to_byteArray(const char* hexStr, unsigned char* byteArray, size_t byteArraySize) {
	size_t len = strlen(hexStr);

	if (len % 2 != 0) {
		printf("Error: Hex string length should be even.\n");
		return;
	}

	if (len / 2 > byteArraySize) {
		printf("Error: Byte array size is insufficient.\n");
		return;
	}

	for (size_t i = 0; i < len; i += 2) {
		int highNibble = hexCharToValue(hexStr[i]);
		int lowNibble = hexCharToValue(hexStr[i + 1]);

		if (highNibble == -1 || lowNibble == -1) {
			printf("Error: Invalid hex character found.\n");
			return;
		}

		byteArray[i / 2] = (unsigned char)((highNibble << 4) | lowNibble);
	}
}

	CLPKM_COM::CLPKM_COM(std::string& id):ID(id){
	CLPKM_N = SM2_N;
	CLPKM_A = SM2_A;
	CLPKM_B = SM2_B;
	isGetKgcPubKey = false;
	isKgc = false;
	isGenKeyPair = false;
#if CLPKM_VERIFY_MODE
	 DAi = testDAi;
#else
	DAi = genRand(CLPKM_N);
#endif
}
	CLPKM_COM::CLPKM_COM(std::string& id, const SM2_BN mpri) :ID(id), mPriKey(mpri) {
		mPubKey.mulGenerator(mPriKey);		//Mpubkey=mPriKey*G
		//验证模式下，暂定KGC的主公钥和加密主公钥一致，并将标志位置位，便于接下来的验证
		setKgcPubKey(mPubKey);
		//在并发执行任务，这里可能要加锁或者换成单例执行模式
		CLPKM_N = SM2_N;
		CLPKM_A = SM2_A;
		CLPKM_B = SM2_B;
		isKgc = true;
		isGenKeyPair = false;
#if CLPKM_VERIFY_MODE
		DAi = testDAi;
#else
		DAi = genRand(CLPKM_N);
#endif
#if CLPKM_DEBUG_PRINT
		printPara("DAi:", DAi);
		printPara("mPriKey:", mPriKey);
		printPara("mPubKey:", mPubKey);
#endif

}
int CLPKM_COM::regenDAi(void)
{
#if CLPKM_VERIFY_MODE
	DAi = testDAi;
#else
	DAi = genRand(CLPKM_N);
#endif
	return 0;
}
int CLPKM_COM::genUA(Epoint& UA)
{
	UA.mulGenerator(DAi);
#if CLPKM_DEBUG_PRINT
	printPara("UA:", UA);
#endif
	return 0;
}
int CLPKM_COM::genDA(Big& TA, Big& DA)
{
	DA = TA + DAi;
	Big zero;
	if (DA<CLPKM_N && DA>zero) {
#if CLPKM_DEBUG_PRINT    
		printPara("DA:", DA);
#endif
		return 0;
	}
	else {
#if CLPKM_DEBUG_PRINT
		printf("DA的输出不满足大于0小于N-1的标准，请重新生成随机数DAi重新运行密钥生成机制！\n");
#endif
		return -1;
	}
}

int CLPKM_COM::genHA(std::string& hexIDA, Big& HA)
{
	//HA 关于用户A的标识、部分椭圆曲线系统参数和系统主公钥的杂凑值。
	unsigned char tmp[4096],ha[32];
	int len = hexIDA.size() * 8 / 2;
	unsigned char* IDA = NULL;
	if (NULL == (IDA = (unsigned char*)malloc(hexIDA.size()/ 2)))  return -1;
	
	hexString_to_byteArray(hexIDA.c_str() ,IDA, len);
	int size = 0;
	unsigned char len_buf[] = {
	static_cast<unsigned char>((len >> 8) & 0xFF),  // 高8位
	static_cast<unsigned char>(len & 0xFF)          // 低8位
	};
	uint8_t a[32],b[32],gx[32],gy[32],mpkey[65];
	CLPKM_A.toBytes(a); CLPKM_B.toBytes(b);
	if (isGetKgcPubKey) {
		kgcPubKey.toBytes(mpkey);
	}
	else {
		std::cout << "Error: Should take the encrypto master public key" << std::endl;
		return -2;
	}
	
	//HA=Hash_sm3_256(ENTLA||IDA||SM2_a||SM2_b||Gx||Gy||mPubKey_x||mPubKey_y)
	//ENTLA是由整数entlenA转换而成的两个字节，entlenA=IDA.size() * 8,为ID的位个数；IDA为bytes形式；hexIDA为ID的十六进制字节码形式
	memcpy(tmp, len_buf, 2);                 size = size + 2;
	memcpy(tmp + size, IDA, len / 8);        size += len / 8;
	memcpy(tmp + size, a, POINT_SIZE);        size += POINT_SIZE;
	memcpy(tmp + size, b, POINT_SIZE);        size += POINT_SIZE;
	memcpy(tmp + size, SM2_xg, POINT_SIZE);       size += POINT_SIZE;
	memcpy(tmp + size, SM2_yg, POINT_SIZE);       size += POINT_SIZE;
	memcpy(tmp + size, mpkey+1, 2 * POINT_SIZE);  size += 2 * POINT_SIZE;

	sm3_digest(tmp, size, ha);
	HA = ha;
#if CLPKM_DEBUG_PRINT
	printPara("HA:", HA);
#endif
	return 0;
}
int CLPKM_COM::genLambda(Epoint& WA, Big& HA, Big& lambda)
{
	//lambda= H256(WA_x‖WA_y‖HA) mod n，
	uint8_t buf[1024], wa[65], ha[32], dgst[32];
	WA.toBytes(wa);
	HA.toBytes(ha);

	int size = 0;
	memcpy(buf, wa + 1, 2 * POINT_SIZE); size += 2 * POINT_SIZE;
	memcpy(buf + size, ha, POINT_SIZE); size += POINT_SIZE;
	sm3_digest(buf, size, dgst);
	lambda = dgst;

	return 0;
}
int CLPKM_COM::genE(std::string& msg, Epoint& WA, Big &HA,Big& E)
{
	unsigned char ZA[1024],ha[32],wa[65],e[32];
	WA.toBytes(wa);
	HA.toBytes(ha);
	int size = 0;
	int h_msgLen = msg.size();
	memcpy(ZA, ha, POINT_SIZE);        size += POINT_SIZE;
	memcpy(ZA + size, wa+1, 2 * POINT_SIZE); size += 2 * POINT_SIZE;
	unsigned char* M = NULL;
	if (NULL == (M = (unsigned char*)malloc(h_msgLen / 2)))  return -1;

	hexString_to_byteArray(msg.c_str(), M, h_msgLen / 2);
	memcpy(ZA + size, M, h_msgLen / 2); size += h_msgLen / 2;
	free(M);
	sm3_digest(ZA, size, e);         //e=Hash256(HA||Wx||Wy||M)
	E = e;

	return 0;
}

int CLPKM_COM::genWA_TA(std::string& IDA, Epoint& UA, Epoint& WA, Big& TA)
{
	if (!isKgc) {
		throw std::logic_error("KGC calls only!");
		return -1;
	}
	Big w,lambda,HA;
#if CLPKM_VERIFY_MODE
	w = testW;
#else
	w= genRand(CLPKM_N);
#endif
	genWA(w, UA, WA);
	
	genHA(IDA, HA);
	genLambda(WA,HA,lambda);
	genTA(w, lambda, TA);
#if CLPKM_DEBUG_PRINT
	printPara("w:", w);
	printPara("lambda:",lambda);
	printPara("HA:", HA);
	printPara("WA:", WA);
	printPara("TA:", TA);
#endif
	return 0;
}
int CLPKM_COM::genWA(Big& w, Epoint& UA,Epoint &WA)
{
	if (!isKgc) {
		throw std::logic_error("KGC calls only!");
		return -1;
	}
	WA.mulGenerator(w);	//WA=[w]G+UA
	WA += UA;	
	return 0;
}
int CLPKM_COM::genTA(Big& w, Big& lambda, Big& TA)
{
	if (!isKgc) {
		throw std::logic_error("KGC calls only!");
		return -1;
	}
	TA += w;
	TA += lambda * mPriKey;//TA = (w + lambda * mPriKey) mod n，
	return 0;
}
int CLPKM_COM::verifyKeyPair(void)
{
	Epoint PA, PAi;
	Big HA, lambda;
	genHA(ID, HA);
	genLambda(pubKey, HA, lambda);
	PA = pubKey + lambda * kgcPubKey;		//PA=pubKey+[lambda]*MpubKey
	PAi.mulGenerator(priKey);				//PAi=[priKey]*G
#if CLPKM_DEBUG_PRINT
	printPara("lambda:", lambda);
	printPara("PA:", PA);
	printPara("PAi:", PAi);
	printPara("pubKey:", pubKey);
	printPara("priKey:", priKey);

#endif
	if (PA == PAi) {
		return 0;
	}
	return -1;
}

int CLPKM_COM::genSign(std::string& msg,SM2_SIGNATURE &sig)
{
	Big E,HA;
	genHA(ID, HA);		//HA的相关计算步骤有待优化
	if (genE(msg, pubKey,HA, E))return -1;
	uint8_t dgst[32];
	E.toBytes(dgst);

	SM2_KEY keyPair;
	priKey.toBytes(keyPair.private_key);
	keyPair.public_key = pubKey.getPoint();		//这里的公钥用不上，但是应该是PA

	sm2_do_sign(&keyPair, dgst, &sig);
#if CLPKM_DEBUG_PRINT
	printPara("E:", E);
	hexCharBuf_print("sigR:", sig.r,POINT_SIZE);
	hexCharBuf_print("sigS:", sig.s, POINT_SIZE);
#endif
	return 0;
}
int CLPKM_COM::verifySign(std::string& IDA, std::string& msg,Epoint& WA,SM2_SIGNATURE &sig)
{
	Big HA,E,lambda ;
	Epoint PA;
	uint8_t dgst[32];

	genHA(IDA, HA);
	genE(msg, WA,HA, E);
	genLambda(WA, HA, lambda);
	
	SM2_KEY keyPair;

	PA = WA + lambda * kgcPubKey;		//PA=pubKey+[lambda]*MpubKey
	keyPair.public_key = PA.getPoint();
	E.toBytes(dgst);
#if CLPKM_DEBUG_PRINT
	printPara("lambda:", lambda);
	printPara("E:", E);
	hexCharBuf_print("sigR:", sig.r, POINT_SIZE);
	hexCharBuf_print("sigS:", sig.s, POINT_SIZE);
#endif
	if (sm2_do_verify(&keyPair, dgst, &sig) != 1) return -3;
	return 0;
}

int CLPKM_COM::encrypt(std::string& IDA, std::string& msg, Epoint& WA, SM2_CIPHERTEXT & encMsg)
{
	Big HA,lambda;
	Epoint PA;

	genHA(IDA, HA);
	genLambda(WA, HA, lambda);

	SM2_KEY keyPair;
	PA = WA + lambda * kgcPubKey;		//PA=pubKey+[lambda]*MpubKey
	keyPair.public_key = PA.getPoint();
	if (sm2_do_encrypt(&keyPair, (uint8_t*)msg.c_str(), msg.size(), &encMsg) != 1) return -1;
#if CLPKM_DEBUG_PRINT
	hexCharBuf_print("PlainText:", (uint8_t*)(msg.c_str()), msg.size());
	hexCharBuf_print("encMsg:", encMsg.ciphertext, encMsg.ciphertext_size);
#endif
	return 0;
}
int CLPKM_COM::decrypt(SM2_CIPHERTEXT& encMsg, std::string& decMsg) {
	SM2_KEY keyPair;
	uint8_t out[1024];
	size_t len = 0;

	priKey.toBytes(keyPair.private_key);
	int ret = sm2_do_decrypt(&keyPair, &encMsg, out, &len);
	if ( ret!= 1) {
		return -1; // 解密失败
	}
	decMsg.assign(reinterpret_cast<char*>(out), len);
#if CLPKM_DEBUG_PRINT
	hexCharBuf_print("DecMsg:", (uint8_t*)decMsg.c_str(),decMsg.size());
#endif
	return 0; // 解密成功
}

//C接口
int genHA(uint8_t* IDA, int len,const SM2_POINT *mPubKey, SM2_BN HA)
{
	//HA 关于用户A的标识、部分椭圆曲线系统参数和系统主公钥的杂凑值。
	uint8_t tmp[256], ha[32];
	int bitLen = len * 8 ;
	int size = 0;
	if (len > 30) { throw std::logic_error("The length of  IDA should less than 30!"); return -1;}
	unsigned char len_buf[] = {
	static_cast<unsigned char>((bitLen >> 8) & 0xFF),  // 高8位
	static_cast<unsigned char>(bitLen & 0xFF)          // 低8位
	};
	
	//HA=Hash_sm3_256(ENTLA||IDA||SM2_a||SM2_b||Gx||Gy||mPubKey_x||mPubKey_y)
	//ENTLA是由整数entlenA转换而成的两个字节，entlenA=IDA.size() * 8,为ID的位个数；IDA为bytes形式；hexIDA为ID的十六进制字节码形式
	memcpy(tmp, len_buf, 2);						size = size + 2;
	memcpy(tmp + size, IDA, len);					size += len ;
	memcpy(tmp + size, SM2_a, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_b, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_xg, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_yg, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, mPubKey->x,POINT_SIZE);		size += POINT_SIZE;
	memcpy(tmp + size, mPubKey->y, POINT_SIZE);		size += POINT_SIZE;

	sm3_digest(tmp, size, ha);
	sm2_bn_from_bytes(HA, ha);
#if CLPKM_DEBUG_PRINT
	sm2_print_bn("C_HA", HA);
#endif
	return 0;
}
int genLambda(const SM2_POINT* pubKey,const SM2_BN HA, SM2_BN lambda)
{
	//lambda= H256(WA_x‖WA_y‖HA) mod n，
	uint8_t buf[128],dgst[32],ha[32];
	int size = 0;
	sm2_bn_to_bytes(HA, ha);
	memcpy(buf, pubKey->x, POINT_SIZE);			size +=  POINT_SIZE;
	memcpy(buf+size, pubKey->y, POINT_SIZE);	size +=  POINT_SIZE;
	memcpy(buf + size, ha, POINT_SIZE);		size +=  POINT_SIZE;

	sm3_digest(buf, size, dgst);
	sm2_bn_from_bytes(lambda, dgst);

#if CLPKM_DEBUG_PRINT
	sm2_print_bn("C_Lambda", lambda);
#endif
	return 0;
}
int genE(uint8_t* msg, int len, const SM2_POINT* pubKey,const SM2_BN HA, SM2_BN E)
{
	//msg为输入的byte型信息
	uint8_t ZA[256],e[32],ha[32];
	int size = 0;
	if (len > 160) { throw std::logic_error("Error: the length of the msg should less than 160!"); return -1; }
	sm2_bn_to_bytes(HA, ha);

	memcpy(ZA, ha, POINT_SIZE);					size += POINT_SIZE;
	memcpy(ZA + size, pubKey->x, POINT_SIZE);		size += POINT_SIZE;
	memcpy(ZA + size, pubKey->y, POINT_SIZE);		size += POINT_SIZE;
	memcpy(ZA + size, msg, len);				size += len;
	
	sm3_digest(ZA, size, e);         //e=Hash256(HA||Wx||Wy||M)
	sm2_bn_from_bytes(E, e);
#if CLPKM_DEBUG_PRINT
	sm2_print_bn("C_E", E);
#endif
	return 0;
}

int genSign_C(uint8_t* ID, int IDlen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey,const SM2_KEY* keyPair, SM2_SIGNATURE* sig)
{
	
	SM2_BN E, HA;
	genHA(ID, IDlen, mPubKey, HA);
	if (genE(msg,msgLen,&(keyPair->public_key),HA,E))return -1;
	uint8_t dgst[32];
	sm2_bn_to_bytes(E, dgst);
	
	 sm2_do_sign(keyPair, dgst,sig);
#if CLPKM_DEBUG_PRINT
	sm2_print_bn("C_E", E);
	hexCharBuf_print("C_sigR:", sig->r, POINT_SIZE);
	hexCharBuf_print("C_sigS:", sig->s, POINT_SIZE);
#endif
	return 0;
}

int verifySign_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_SIGNATURE* sig)
{
	SM2_BN HA, E, lambda;
	SM2_POINT PA;
	uint8_t dgst[32];

	genHA(IDA, IDALen, mPubKey, HA);
	if (genE(msg, msgLen, pubKeyA, HA, E))return -1;
	genLambda(pubKeyA, HA, lambda);

	SM2_KEY keyPair;
	uint8_t blambda[32];
	sm2_bn_to_bytes(lambda, blambda);
	SM2_POINT tmp;
	sm2_point_mul(&tmp, blambda, mPubKey);
	sm2_point_add(&PA, &tmp, pubKeyA);	//PA=pubKey+[lambda]*MpubKey
	keyPair.public_key = PA;
	sm2_bn_to_bytes(E, dgst);

#if CLPKM_DEBUG_PRINT
	sm2_print_bn("C_lambda", lambda);
	sm2_print_bn("C_E", E);
	hexCharBuf_print("C_sigR:", sig->r, POINT_SIZE);
	hexCharBuf_print("C_sigS:", sig->s, POINT_SIZE);
#endif
	if (sm2_do_verify(&keyPair, dgst, sig) != 1) return -3;
	return 0;
}

int encrypt_C(uint8_t* IDA, int IDALen, uint8_t* msg, int msgLen, const SM2_POINT* mPubKey, const SM2_POINT* pubKeyA, SM2_CIPHERTEXT* encMsg)
{
	SM2_BN HA, lambda;
	SM2_POINT PA;

	genHA(IDA, IDALen, mPubKey, HA);
	genLambda(pubKeyA, HA, lambda);

	SM2_KEY keyPair;
	uint8_t blambda[32];
	sm2_bn_to_bytes(lambda, blambda);
	SM2_POINT tmp;
	sm2_point_mul(&tmp, blambda, mPubKey);
	sm2_point_add(&PA, &tmp, pubKeyA);	//PA=pubKey+[lambda]*MpubKey
	keyPair.public_key = PA;

	if (sm2_do_encrypt(&keyPair, msg, msgLen, encMsg) != 1) return -1;
#if CLPKM_DEBUG_PRINT
	printf("PlainText:%s", msg);
	hexCharBuf_print("PlainText_HEX:", msg, msgLen);
	hexCharBuf_print("enMsg:", encMsg->ciphertext, encMsg->ciphertext_size);
#endif
	return 0;
}
int decrypt_C(SM2_CIPHERTEXT* encMsg, const SM2_KEY* keyPair, uint8_t* decMsg, int* decMsgLen)
{
	size_t len = 0;
	int ret = sm2_do_decrypt(keyPair, encMsg, decMsg,&len);
	if (ret != 1) {
		return -1; // 解密失败
	}
	*decMsgLen = len;
#if CLPKM_DEBUG_PRINT
	hexCharBuf_print("DecMsg_HEX:",decMsg, *decMsgLen);
#endif
	return 0; // 解密成功
}
