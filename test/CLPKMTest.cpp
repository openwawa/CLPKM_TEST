#include <CLPKM/clpkm.h>

int CLPKMTest() {
	SM2_BN ms = {
	0xF19A9FF9, 0x2B3535C9, 0xD7E99C97, 0x08319FF7,
	0xC1C932C2, 0xFE0F6388, 0x10F79415, 0x6BDD93B2 };		//主私钥
	std::string devId = "416c696365",devId1="416c69636542", kgcId = "426f62";
	
	CLPKM_COM* dev, *kgc;
	dev = new CLPKM_COM(devId);				//实例化为普通设备对象	
	kgc = new CLPKM_COM(kgcId, ms);			//实例化为KGC设备对象
	
	printf("********************CPP&&Complete Interface Test!********************\n");
	Epoint MpubKey, UA, WA;
	Big HA, TA, DA;
	/*DEVs生成UA，并将{devId、UA}安全发送到KGC */
	dev->genUA(UA);
	/*KGC生成WA、TA并将{MpubKey、WA、TA}安全发送到DEV*/
	/*KGC将TA返回DEV时可使用UA作为公钥使用加密方法ENC加密包括TA的数据后将密文传递到DEV。DEV使用DAi解密密文后还原包括TA的数据。*/
	kgc->genWA_TA(devId, UA, WA, TA);
	MpubKey = kgc->getMPubKey();
	
	/*DEV 接受到MpubKey、WA、TA后，设置kgc主公钥和公钥,根据TA生成设备私钥DA*/
	dev->setKgcPubKey(MpubKey);
	if (dev->genDA(TA, DA) != 0) {
		printf("Private key generation failed, key generation process terminated!\n");
		return -3;
	}
	/*DA为私钥，WA为公钥，将密钥对保存在对象中*/
	dev->setKeyPair(DA, WA);
	/*DEV校验密钥的正确性*/
	if (dev->verifyKeyPair() != 0) {
		printf("Failed verify keyPair\n");
		return -2;
	}
	else {
		printf("Success verify keyPair\n");
	}
	SM2_SIGNATURE sig;
	std::string msg="6D65737361676520646967657374";
	dev->genSign(msg,sig);
	//验签这里的WA为dev公钥
	if (kgc->verifySign(devId, msg,WA,sig) != 0) {
		printf("Failed to verify signature!\n");
	}
	else {
		printf("Success to verify signature!\n");
	}
	SM2_CIPHERTEXT encMsg;
	std::string plainText="This is test text!";
	std::string decMsg;
	//这里的WA为dev公钥
	if (kgc->encrypt(devId, msg, WA, encMsg)!=0) {
		printf("Generate encrypto msg successful!\n");
	}
	else {
		std::cout << "encMsg:" << encMsg.ciphertext << std::endl;
	}
	if (dev->decrypt(encMsg, decMsg) != 0) {
		printf("Failed to decrypto msg!");
	}
	else {
		std::cout << "decMsg:" << decMsg << std::endl;
	}

	
	printf("**************************C Interface Test!****************************\n");
	SM2_BN SM2_HA, SM2_lambda, SM2_E;
	SM2_POINT SM2_WA;
	unsigned char name[] = "Alice";
	unsigned char dmsg[] = "message digest";
	SM2_KEY dev_keyPair = dev->getKeyPair(),kgc_keyPair=kgc->getKeyPair();
	SM2_SIGNATURE c_sig;
	SM2_CIPHERTEXT c_encMsg;
	uint8_t c_decMsg[1024];
	int c_decMsgLen = 0;

	genSign_C(name, strlen((const char*)name), dmsg, strlen((const char*)dmsg), MpubKey.getPointPtr(), &dev_keyPair,&c_sig);
	if (verifySign_C(name, strlen((const char*)name), dmsg, strlen((const char*)dmsg), MpubKey.getPointPtr(), &dev_keyPair.public_key, &c_sig) != 0) {
		printf("Failed to verify signature!\n");
	}
	else {
		printf("Success to verify signature!\n");
	}
	encrypt_C(name, strlen((const char*)name), dmsg, strlen((const char*)dmsg), MpubKey.getPointPtr(), &dev_keyPair.public_key, &c_encMsg);
	std::cout << "encMsg:" << c_encMsg.ciphertext << std::endl;
	if (decrypt_C(&c_encMsg,&dev_keyPair,c_decMsg,&c_decMsgLen) != 0) {
		printf("Failed to decrypto msg!");
	}
	else {
		std::cout << "decMsg:" << c_decMsg << std::endl;
	}

	delete kgc;
	delete dev;
	return 0;
}