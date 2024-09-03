#include <CLPKM/big.h>


Big operator+(const Big& a, const Big&b) {
	Big bg;
	sm2_fn_add(bg.big, a.big, b.big);		//ʹ��������ļӼ���
	return bg;
}

Big operator-(const Big& a, const Big& b) {
	Big bg;
	sm2_fn_sub(bg.big, a.big, b.big);
	return bg;
}
Big operator*(const Big& a, const Big& b) {
	Big ret;
	sm2_fn_mul(ret.big, a.big, b.big);		//����SM2��BIG �ĳ˷��õ���������ĳ˷�
	return ret;
}

bool operator>=(const Big& a, const Big& b) {
	if (sm2_bn_cmp(a.big, b.big) != -1) return true;
	return false;
}
bool operator>(const Big& a, const Big& b) {
	if (sm2_bn_cmp(a.big, b.big) == 1) return true;
	return false;
}
bool operator<=(const Big& a, const Big& b) {
	if (sm2_bn_cmp(a.big, b.big) != 1) return true;
	return false;
}
bool operator<(const Big& a, const Big& b) {
	if (sm2_bn_cmp(a.big, b.big) == -1) return true;
	return false;
}
bool operator==(const Big& a, const Big& b) {
	if (sm2_bn_cmp(a.big, b.big) == 0) return true;
	return false;
}
Big genRand(const Big& range) {		//ret<=range
	Big ret;
	sm2_bn_rand_range(ret.big, range.big);
	return ret;
}