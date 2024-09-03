#include <CLPKM/clpkm.h>

int CLPKMTest() {
	SM2_BN ms = {
	0xF19A9FF9, 0x2B3535C9, 0xD7E99C97, 0x08319FF7,
	0xC1C932C2, 0xFE0F6388, 0x10F79415, 0x6BDD93B2 };		//��˽Կ
	std::string devId = "416c696365",devId1="416c69636542", kgcId = "426f62";
	
	CLPKM_COM* dev, *kgc;
	dev = new CLPKM_COM(devId);				//ʵ����Ϊ��ͨ�豸����	
	kgc = new CLPKM_COM(kgcId, ms);			//ʵ����ΪKGC�豸����
	
	printf("********************CPP&&Complete Interface Test!********************\n");
	Epoint MpubKey, UA, WA;
	Big HA, TA, DA;
	/*DEVs����UA������{devId��UA}��ȫ���͵�KGC */
	dev->genUA(UA);
	/*KGC����WA��TA����{MpubKey��WA��TA}��ȫ���͵�DEV*/
	/*KGC��TA����DEVʱ��ʹ��UA��Ϊ��Կʹ�ü��ܷ���ENC���ܰ���TA�����ݺ����Ĵ��ݵ�DEV��DEVʹ��DAi�������ĺ�ԭ����TA�����ݡ�*/
	kgc->genWA_TA(devId, UA, WA, TA);
	MpubKey = kgc->getMPubKey();
	
	/*DEV ���ܵ�MpubKey��WA��TA������kgc����Կ�͹�Կ,����TA�����豸˽ԿDA*/
	dev->setKgcPubKey(MpubKey);
	if (dev->genDA(TA, DA) != 0) {
		printf("Private key generation failed, key generation process terminated!\n");
		return -3;
	}
	/*DAΪ˽Կ��WAΪ��Կ������Կ�Ա����ڶ�����*/
	dev->setKeyPair(DA, WA);
	/*DEVУ����Կ����ȷ��*/
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
	//��ǩ�����WAΪdev��Կ
	if (kgc->verifySign(devId, msg,WA,sig) != 0) {
		printf("Failed to verify signature!\n");
	}
	else {
		printf("Success to verify signature!\n");
	}
	SM2_CIPHERTEXT encMsg;
	std::string plainText="This is test text!";
	std::string decMsg;
	//�����WAΪdev��Կ
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