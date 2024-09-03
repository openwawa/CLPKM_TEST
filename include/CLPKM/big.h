#include <gmssl/sm2.h>
#ifndef __BIG_H__
#define __BIG_H__
/**************************************************************************
 * 功能：大数类型封装，包含大数类型的基本运算
 *   3W：240429 交子 wwj
 * 
***************************************************************************/
#define __CHECK_INPUT(x)
#define BNSIZE 8
class Big {
	SM2_BN big;
public:
	Big() { uint8_t in[32] = {}; sm2_bn_from_bytes(big, in); }
	Big(uint8_t in[32]) { sm2_bn_from_bytes(big, in); }
	Big(char hex[64]) { sm2_bn_from_hex(big, hex); }
	Big(const SM2_BN bn) { copy(bn, big); }
	Big(Big& b) { copy(b.big,big); }
	Big(uint32_t num) { sm2_bn_set_word(big, num);}


	Big& operator=(const Big& b) { copy(b.big, big); return *this; }
	Big& operator=(SM2_BN bn) { copy(bn, big); return *this; }
	Big& operator=(const SM2_BN bn) { copy(bn, big); return *this; }
	Big& operator=(uint8_t in[32]) { sm2_bn_from_bytes(big, in); return *this; }
	Big& operator=(uint32_t num) { sm2_bn_set_word(big,num); return *this;}

	Big& operator+=(const Big& b) { sm2_fn_add(big, b.big, big); return *this; }
	Big& operator-=(const Big& b) { sm2_fn_sub(big, b.big, big); return *this; }

	const SM2_BN& getBN(void) { return big; }

	void toBytes(uint8_t out[32])const { sm2_bn_to_bytes(big, out);}
	void toHex(char hex[64]) { sm2_bn_to_hex(big,hex);}
	void toBit(char bits[256]) { sm2_bn_to_bits(big, bits); }

	bool isZero(void) { return sm2_bn_is_zero(big); }
	bool isOne(void) { return sm2_bn_is_one(big); }
	bool isOdd(void) { return sm2_bn_is_odd(big); }

	friend Big operator+(const Big&, const Big&);
	friend Big operator-(const Big&, const Big&);
	friend Big operator*(const Big&, const Big&);
	friend bool operator>=(const Big& , const Big& );
	friend bool operator>(const Big& , const Big& );
	friend bool operator<=(const Big& , const Big& );
	friend bool operator<(const Big& , const Big& );
	friend bool operator==(const Big& , const Big& );
	friend Big genRand(const Big&range);

private:
	void copy(const SM2_BN src, SM2_BN dst) { for (int i = 0; i < BNSIZE; i++) dst[i] = src[i]; }

};
Big operator*(const Big&, const Big&);
#endif