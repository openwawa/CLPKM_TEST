#include <CLPKM/epoint.h>


void Epoint::copy(const SM2_POINT& src, SM2_POINT& dst) {
	for (int i = 0; i < POINT_SIZE; i++) {
		dst.x[i] = src.x[i];
		dst.y[i] = src.y[i];
	}
}
 
Epoint operator+(const Epoint& ep1, const Epoint& ep2) {
	Epoint ret;
	sm2_point_add(&ret.point, &ep1.point, &ep2.point);
	return ret;
}
Epoint operator-(const Epoint& ep1, const Epoint& ep2) {
	Epoint ret;
	sm2_point_sub(&ret.point, &ep1.point, &ep2.point);
	return ret;

}
Epoint operator*(const Big& b, const Epoint& ep) {
	Epoint ret;
	uint8_t bstr[32];
	b.toBytes(bstr);
	sm2_point_mul(&ret.point,bstr, &ep.point);
	return ret;
}
bool operator==(const Epoint& ep1, const Epoint& ep2) {
	if (memcmp(&ep1.point, &ep2.point, sizeof(SM2_POINT)) == 0) {
		return true;
	}
	return false;
}