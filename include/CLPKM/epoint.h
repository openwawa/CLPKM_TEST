#include <gmssl/sm2.h>
#include <CLPKM/big.h>
#ifndef __EPONIT_H__
#define __EPOINT_H__
/**************************************************************************
 * 功能：椭圆曲线点类型封装，包含椭圆曲线点类型的基本运算
 *   3W：240430 交子 wawaji
 *
***************************************************************************/
#define __CHECK_INPUT(x)
#define POINT_SIZE 32
class Epoint {
	SM2_POINT point;
public:
	Epoint() { sm2_point_init(&point); }
	Epoint(Big& bx, Big& by) {uint8_t x[32], y[32];bx.toBytes(x); by.toBytes(y);sm2_point_from_xy(&point, x, y);}
	Epoint(uint8_t x[32],int y) { sm2_point_from_x(&point, x,y); }
	Epoint(uint8_t x[32], uint8_t y[32]) { sm2_point_from_xy(&point, x, y);}
	


	Epoint& operator=(const Epoint& ep) { copy(ep.point, point); return *this; }
	//Epoint operator=(const Epoint& ep) { copy(ep.point, point); return *this; }
	Epoint& operator=(SM2_POINT& sm2Point) { copy(sm2Point, point); return *this; }
	Epoint& operator=(const SM2_POINT& sm2Point) { copy(sm2Point, point); return *this; }
	Epoint& operator=(uint8_t in[64]) { sm2_point_from_octets(&point,in,POINT_SIZE*2); return *this; }


	Epoint& operator+=(const Epoint& ep) { sm2_point_add(&point,&point,&ep.point); return *this; }
	Epoint& operator-=(const Epoint& ep) { sm2_point_sub(&point,&point,&ep.point); return *this; }
	Epoint& mulGenerator(Big& bg) { uint8_t in[32]; bg.toBytes(in); sm2_point_mul_generator(&point, in); return *this; }	//this=bg*G

	const SM2_POINT getPoint(void) { return point; }
	const SM2_POINT* getPointPtr(void) { return &point; }
	void toBytes(uint8_t x[32], uint8_t y[32]) {
		uint8_t out[65];
		sm2_point_to_uncompressed_octets(&point, out);
		for (int i = 0; i < POINT_SIZE; i++) {			//gmssl 中的输出第一个参数里为0x04 ===>*out++ = 0x04;
			x[i] = out[i+1];
			y[i] = out[1+i + POINT_SIZE];
		}
	}
	void toBytes(uint8_t out[65]) { sm2_point_to_uncompressed_octets(&point, out); }
	
	bool isOnCurve(void) { return sm2_point_is_on_curve(&point);}
	bool isAtInfinity(void) { return sm2_point_is_at_infinity(&point);}

	friend Epoint operator+(const Epoint&ep1, const Epoint&ep2);
	friend bool operator==(const Epoint& ep1, const Epoint& ep2);
	friend Epoint operator-(const Epoint&ep1, const Epoint&ep2);
	friend Epoint operator*(const Big& b,const Epoint& ep);

private:
	void copy(const SM2_POINT& src, SM2_POINT& dst);

};
#endif