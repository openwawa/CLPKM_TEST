
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include "hip/hip_runtime.h"
#include <gmssl/asn1.h>
#include <unistd.h>

__device__ const SM2_BN SM2_P_HIP = {
	0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

__device__ const SM2_BN SM2_B_HIP = {
	0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
	0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
};

__device__ const SM2_JACOBIAN_POINT _SM2_G_HIP = {
	{
	0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
	0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
	},
	{
	0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
	0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
	},
	{
	1, 0, 0, 0, 0, 0, 0, 0,
	},
};
__device__ const SM2_JACOBIAN_POINT *SM2_G_HIP = &_SM2_G_HIP;

__device__ const SM2_BN SM2_N_HIP = {
	0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

__device__ const SM2_BN SM2_ONE_HIP = {1,0,0,0,0,0,0,0};
__device__ const SM2_BN SM2_TWO_HIP = {2,0,0,0,0,0,0,0};
__device__ const SM2_BN SM2_THREE_HIP = {3,0,0,0,0,0,0,0};

// u = (p - 1)/4, u + 1 = (p + 1)/4
__device__ const SM2_BN SM2_U_PLUS_ONE_HIP = {
	0x00000000, 0x40000000, 0xc0000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xbfffffff, 0x3fffffff,
};

__device__ void sm2_bn_set_word_hip(SM2_BN r, uint32_t a)
{
	int i;
	r[0] = a;
	for (i = 1; i < 8; i++) {
		r[i] = 0;
	}
}

__device__ int strcmp_hip(const char *str1,const char *str2)
{
	if(str1==NULL||str2==NULL)
	{
		return -2;
	}
	int ret=0;
	while(!(ret=*str1-*str2)&&*str1)
	{
		str1++;
		str2++;
	}
	if(*str1>*str2)
	{
		ret = 1;
	}
	if(*str1<*str2)
	{
		ret = -1;
	}
	return ret;
}

__device__ int asn1_length_to_der_hip(size_t len, uint8_t **out, size_t *outlen)
{
	if (len > INT_MAX) {
		 
		return -1;
	}
	if (!outlen) {
		 
		return -1;
	}

	if (len < 128) {
		if (out && *out) {
			*(*out)++ = (uint8_t)len;
		}
		(*outlen)++;

	} else {
		uint8_t buf[4];
		int nbytes;

		if (len < 256) nbytes = 1;
		else if (len < 65536) nbytes = 2;
		else if (len < (1 << 24)) nbytes = 3;
		else nbytes = 4;
		PUTU32(buf, (uint32_t)len);

		if (out && *out) {
			*(*out)++ = 0x80 + nbytes;
			memcpy(*out, buf + 4 - nbytes, nbytes);
			(*out) += nbytes;
		}
		(*outlen) += 1 + nbytes;
	}
	return 1;
}

__device__ int asn1_length_from_der_hip(size_t *len, const uint8_t **in, size_t *inlen)
{
	if (!len || !in || !(*in) || !inlen) {
		 
		return -1;
	}

	if (*inlen == 0) {
		 
		return -1;
	}

	if (**in < 128) {
		*len = *(*in)++;
		(*inlen)--;

	} else {
		uint8_t buf[4] = {0};
		int nbytes  = *(*in)++ & 0x7f;
		(*inlen)--;

		if (nbytes < 1 || nbytes > 4) {
			 
			return -1;
		}
		if (*inlen < nbytes) {
			 
			return -1;
		}

		memcpy(buf + 4 - nbytes, *in, nbytes);
		*len = (size_t)GETU32(buf);
		*in += nbytes;
		*inlen -= nbytes;
	}

	// check if the left input is enough for reading (d,dlen)
	if (*inlen < *len) 
		return -2;
	return 1;
}

// asn1_data_to_der_hip do not check the validity of data
__device__ int asn1_data_to_der_hip(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		 
		return -1;
	}
	if (datalen == 0) {
		return 0;
	}
	if (out && *out) {
		if (!data) {
			 
			return -1;
		}
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
	return 1;
}

// not in-use
__device__ int asn1_data_from_der_hip(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	if (!data || !datalen || !in || !(*in) || !inlen) {
		 
		return -1;
	}
	if (*inlen < datalen) {
		 
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

__device__ int asn1_header_to_der_hip(int tag, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		 
		return -1;
	}

	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;

	(void)asn1_length_to_der_hip(dlen, out, outlen);
	return 1;
}

__device__ int asn1_type_to_der_hip(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		 
		return -1;
	}

	if (!d) {
		if (dlen) {
			 
			return -1;
		}
		return 0;
	}

	// tag
	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;

	// length
	(void)asn1_length_to_der_hip(dlen, out, outlen);

	// data
	if (out && *out) {
		memcpy(*out, d, dlen);
		*out += dlen;
	}
	*outlen += dlen;

	return 1;
}

__device__ int asn1_type_from_der_hip(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	if (!d || !dlen || !in || !(*in) || !inlen) {
		 
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*d = NULL;
		*dlen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length
	if (asn1_length_from_der_hip(dlen, in, inlen) != 1) {
		 
		return -1;
	}

	// data
	*d = *in;
	*in += *dlen;
	*inlen -= *dlen;
	return 1;
}

__device__ int asn1_nonempty_type_to_der_hip(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;

	if (d && dlen == 0) {
		 
		return -1;
	}
	if ((ret = asn1_type_to_der_hip(tag, d, dlen, out, outlen)) != 1) {
		if (ret)  
		return ret;
	}
	return 1;
}

__device__ int asn1_nonempty_type_from_der_hip(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_type_from_der_hip(tag, d, dlen, in, inlen)) != 1) {
		if (ret)  
		return ret;
	}
	if (*dlen == 0) {
		 
		return -1;
	}
	return 1;
}

__device__ int asn1_any_type_from_der_hip(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	if (!tag || !d || !dlen || !in || !(*in) || !inlen) {
		 
		return -1;
	}

	if (*inlen == 0) {
		*tag = - 1;
		*d = NULL;
		*dlen = 0;
		return 0;
	}

	*tag = *(*in)++;
	(*inlen)--;

	if (asn1_length_from_der_hip(dlen, in, inlen) != 1) {
		 
		return -1;
	}

	*d = *in;
	*in += *dlen;
	*inlen -= *dlen;
	return 1;
}

// we need to check this is an asn.1 type
__device__ int asn1_any_to_der_hip(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		 
		return -1;
	}

	if (!a) {
		if (a) {
			 
			return -1;
		}
		return 0;
	}

	if (out && *out) {
		memcpy(*out, a, alen);
		*out += alen;
	}
	*outlen += alen;

	return 1;
}

__device__ int asn1_any_from_der_hip(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;
	const uint8_t *d;
	size_t dlen;

	if (!a || !alen || !in || !(*in) || !inlen) {
		 
		return -1;
	}
	*a = *in;
	*alen = *inlen;

	if ((ret = asn1_any_type_from_der_hip(&tag, &d, &dlen, in, inlen)) != 1) {
		if (ret)  
		return ret;
	}
	*alen -= *inlen;

	return 1;
}

__device__ const char *asn1_boolean_name_hip(int val)
{
	switch (val) {
	case 1: return "true";
	case 0: return "false";
	}
	return NULL;
}

__device__ int asn1_boolean_from_name_hip(int *val, const char *name)
{
	if (strcmp_hip(name, "true") == 0) {
		*val = 1;
		return 1;
	} else if (strcmp_hip(name, "false") == 0) {
		*val = 0;
		return 1;
	}
	*val = -1;
	return -1;
}

__device__ int asn1_integer_to_der_ex_hip(int tag, const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		return -1;
	}

	if (!a) {
		return 0;
	}
	if (alen <= 0 || alen > INT_MAX) {
		return -1;
	}

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;

	while (*a == 0 && alen > 1) {
		a++;
		alen--;
	}

	if (a[0] & 0x80) {
		asn1_length_to_der_hip(alen + 1, out, outlen);
		if (out && *out) {
			*(*out)++ = 0x00;
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += 1 + alen;
	} else {
		asn1_length_to_der_hip(alen, out ,outlen);
		if (out && *out) {
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += alen;
	}
	return 1;
}

__device__ int asn1_integer_from_der_ex_hip(int tag, const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	size_t len;

	if (!a || !alen || !in || !(*in) || !inlen) {
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*a = NULL;
		*alen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (not zero)
	if (asn1_length_from_der_hip(&len, in, inlen) != 1) {
		return -1;
	}
	if (len == 0) {
		return -1;
	}

	// check if ASN1_INTEGER is negative
	if (**in & 0x80) {
		return -1;
	}

	// remove leading zero
	if (**in == 0 && len > 1) {
		(*in)++;
		(*inlen)--;
		len--;

		// the following bit should be one
		if (((**in) & 0x80) == 0) {
			return -1;
		}
	}

	// no leading zeros
	if (**in == 0 && len > 1) {
		return -1;
	}

	// return integer bytes
	*a = *in;
	*alen = len;
	*in += len;
	*inlen -= len;
	return 1;
}

__device__ int asn1_length_le_hip(size_t len1, size_t len2)
{
	if (len1 > len2) {
		return -1;
	}
	return 1;
}

__device__ int asn1_length_is_zero_hip(size_t len)
{
	if (len) {
		return -1;
	}
	return 1;
}


__device__ int sm2_signature_from_der_hip(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *r;
	size_t rlen;
	const uint8_t *s;
	size_t slen;

	if ((ret = asn1_type_from_der_hip(ASN1_TAG_SEQUENCE,&d, &dlen, in, inlen)) != 1) {
		return ret;
	}
	if (asn1_integer_from_der_ex_hip(ASN1_TAG_INTEGER,&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der_ex_hip(ASN1_TAG_INTEGER,&s, &slen, &d, &dlen) != 1
		|| asn1_length_le_hip(rlen, 32) != 1
		|| asn1_length_le_hip(slen, 32) != 1
		|| asn1_length_is_zero_hip(dlen) != 1) {
		return -1;
	}
	memset(sig, 0, sizeof(*sig));
	memcpy(sig->r + 32 - rlen, r, rlen);
	memcpy(sig->s + 32 - slen, s, slen);
	return 1;
}


__device__ int mem_is_zero_hip(const uint8_t *buf, size_t len)
{
	int ret = 1;
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i]) ret = 0;
	}
	return ret;
}


__device__ __host__ int sm2_bn_is_zero_hip(const SM2_BN a)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

__device__ int sm2_bn_is_one_hip(const SM2_BN a)
{
	int i;
	if (a[0] != 1)
		return 0;
	for (i = 1; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

__device__ void sm2_bn_to_bytes_hip(const SM2_BN a, uint8_t out[32])
{
	int i;
	uint8_t *p = out;


	for (i = 7; i >= 0; i--) {
		uint32_t ai = (uint32_t)a[i];
		PUTU32(out, ai);
		out += sizeof(uint32_t);
	}

}

__device__ static int hexchar2int(char c)
{
	if      ('0' <= c && c <= '9') return c - '0';
	else if ('a' <= c && c <= 'f') return c - 'a' + 10;
	else if ('A' <= c && c <= 'F') return c - 'A' + 10;
	else return -1;
}

__device__ static int hex2bin(const char *in, size_t inlen, uint8_t *out)
{
	int c;
	if (inlen % 2)
		return -1;

	while (inlen) {
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out = (uint8_t)c << 4;
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out |= (uint8_t)c;
		inlen -= 2;
		out++;
	}
	return 1;
}

__device__ void sm2_bn_from_bytes_hip(SM2_BN r, const uint8_t in[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		r[i] = GETU32(in);
		in += sizeof(uint32_t);
	}
}

__device__ int sm2_bn_from_hex_hip(SM2_BN r, const char hex[64])
{
	uint8_t buf[32];
	if (hex2bin(hex, 64, buf) < 0)
		return -1;
	sm2_bn_from_bytes_hip(r, buf);
	return 1;
}

__device__ int sm2_bn_from_asn1_integer_hip(SM2_BN r, const uint8_t *d, size_t dlen)
{
	uint8_t buf[32] = {0};
	if (!d || dlen == 0) {
		return -1;
	}
	if (dlen > sizeof(buf)) {
		return -1;
	}
	memcpy(buf + sizeof(buf) - dlen, d, dlen);
	sm2_bn_from_bytes_hip(r, buf);
	return 1;
}

__device__ void sm2_bn_to_bits_hip(const SM2_BN a, char bits[256])
{
	int i, j;
	uint64_t w;
	for (i = 7; i >= 0; i--) {
		w = a[i];
		for (j = 0; j < 32; j++) {
			*bits++ = (w & 0x80000000) ? '1' : '0';
			w <<= 1;
		}
	}
}

__device__ int sm2_bn_cmp_hip(const SM2_BN a, const SM2_BN b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

__device__ int rand_bytes_hip(uint8_t *buf, size_t len,unsigned int r)
{
	if (!buf) {
		return -1;
	}
	if (!len || len > 256) {
		return -1;
	}
	for(int i=0;i<len;i++){
		buf[i] = r%256;
	}
	return 1;
}

__device__ int sm2_bn_rand_range_hip(SM2_BN r, const SM2_BN range,unsigned int rd)
{
	uint8_t buf[32];
	do {
		if (rand_bytes_hip(buf, sizeof(buf),rd) != 1) {
			return -1;
		}
		sm2_bn_from_bytes_hip(r, buf);
	} while (sm2_bn_cmp_hip(r, range) >= 0);
	return 1;
}

__device__ int sm2_fn_rand_hip(SM2_BN r,unsigned int rd)
{
	if (sm2_bn_rand_range_hip(r, SM2_N_HIP,rd) != 1) {
		return -1;
	}
	return 1;
}

__device__ int sm2_bn_is_odd_hip(const SM2_BN a)
{
	return a[0] & 0x01;
}

__device__ int sm2_bn_rshift_hip(SM2_BN ret, const SM2_BN a, unsigned int nbits)
{
	SM2_BN r;
	int i;

	if (nbits > 31) {
		return -1;
	}
	if (nbits == 0) {
		sm2_bn_copy(ret, a);
	}
	for (i = 0; i < 7; i++) {
		r[i] = a[i] >> nbits;
		r[i] |= (a[i+1] << (32 - nbits)) & 0xffffffff;
	}
	r[i] = a[i] >> nbits;
	sm2_bn_copy(ret, r);
	return 1;
}

__device__ void sm2_bn_add_hip(SM2_BN r, const SM2_BN a, const SM2_BN b)
{
	int i;
	r[0] = a[0] + b[0];

	for (i = 1; i < 8; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 7; i++) {
		r[i] &= 0xffffffff;
	}
}

__device__ void sm2_bn_sub_hip(SM2_BN ret, const SM2_BN a, const SM2_BN b)
{
	int i;
	SM2_BN r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	sm2_bn_copy(ret, r);
}

__device__ void sm2_fp_add_hip(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	sm2_bn_add_hip(r, a, b);
	if (sm2_bn_cmp_hip(r, SM2_P_HIP) >= 0) {
		sm2_bn_sub_hip(r, r, SM2_P_HIP);
	}
}

__device__ void sm2_fp_sub_hip(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	if (sm2_bn_cmp_hip(a, b) >= 0) {
		sm2_bn_sub_hip(r, a, b);
	} else {
		SM2_BN t;
		sm2_bn_sub_hip(t, SM2_P_HIP, b);
		sm2_bn_add_hip(r, t, a);
	}
}

__device__ void sm2_fp_dbl_hip(SM2_Fp r, const SM2_Fp a)
{
	sm2_fp_add_hip(r, a, a);
}

__device__ void sm2_fp_tri_hip(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN t;
	sm2_fp_dbl_hip(t, a);
	sm2_fp_add_hip(r, t, a);
}

__device__ void sm2_fp_div2_hip(SM2_Fp r, const SM2_Fp a)
{
	int i;
	sm2_bn_copy(r, a);
	if (r[0] & 0x01) {
		sm2_bn_add_hip(r, r, SM2_P_HIP);
	}
	for (i = 0; i < 7; i++) {
		r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
	}
	r[i] >>= 1;
}

__device__ void sm2_fp_neg_hip(SM2_Fp r, const SM2_Fp a)
{
	if (sm2_bn_is_zero_hip(a)) {
		sm2_bn_copy(r, a);
	} else {
		sm2_bn_sub_hip(r, SM2_P_HIP, a);
	}
}

__device__ void sm2_fp_mul_hip(SM2_Fp r, const SM2_Fp a, const SM2_Fp b)
{
	int i, j;
	uint64_t s[16] = {0};
	SM2_BN d = {0};
	uint64_t u;

	// s = a * b
	for (i = 0; i < 8; i++) {
		u = 0;
		for (j = 0; j < 8; j++) {
			u = s[i + j] + a[i] * b[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 8] = u;
	}

	r[0] = s[0] + s[ 8] + s[ 9] + s[10] + s[11] + s[12] + ((s[13] + s[14] + s[15]) << 1);
	r[1] = s[1] + s[ 9] + s[10] + s[11] + s[12] + s[13] + ((s[14] + s[15]) << 1);
	r[2] = s[2];
	r[3] = s[3] + s[ 8] + s[11] + s[12] + s[14] + s[15] + (s[13] << 1);
	r[4] = s[4] + s[ 9] + s[12] + s[13] + s[15] + (s[14] << 1);
	r[5] = s[5] + s[10] + s[13] + s[14] + (s[15] << 1);
	r[6] = s[6] + s[11] + s[14] + s[15];
	r[7] = s[7] + s[ 8] + s[ 9] + s[10] + s[11] + s[15] + ((s[12] + s[13] + s[14] + s[15]) << 1);

	for (i = 1; i < 8; i++) {
		r[i] += r[i - 1] >> 32;
		r[i - 1] &= 0xffffffff;
	}

	d[2] = s[8] + s[9] + s[13] + s[14];
	d[3] = d[2] >> 32;
	d[2] &= 0xffffffff;
	sm2_bn_sub_hip(r, r, d);

	// max times ?
	while (sm2_bn_cmp_hip(r, SM2_P_HIP) >= 0) {
		sm2_bn_sub_hip(r, r, SM2_P_HIP);
	}
}

__device__ void sm2_fp_sqr_hip(SM2_Fp r, const SM2_Fp a)
{
	sm2_fp_mul_hip(r, a, a);
}

__device__ void sm2_fp_exp_hip(SM2_Fp r, const SM2_Fp a, const SM2_Fp e)
{
	SM2_BN t;
	uint32_t w;
	int i, j;

	sm2_bn_set_word_hip(t,1);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm2_fp_sqr_hip(t, t);
			if (w & 0x80000000)
				sm2_fp_mul_hip(t, t, a);
			w <<= 1;
		}
	}

	sm2_bn_copy(r, t);
}

__device__ void sm2_fp_inv_hip(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN a1;
	SM2_BN a2;
	SM2_BN a3;
	SM2_BN a4;
	SM2_BN a5;
	int i;

	sm2_fp_sqr_hip(a1, a);
	sm2_fp_mul_hip(a2, a1, a);
	sm2_fp_sqr_hip(a3, a2);
	sm2_fp_sqr_hip(a3, a3);
	sm2_fp_mul_hip(a3, a3, a2);
	sm2_fp_sqr_hip(a4, a3);
	sm2_fp_sqr_hip(a4, a4);
	sm2_fp_sqr_hip(a4, a4);
	sm2_fp_sqr_hip(a4, a4);
	sm2_fp_mul_hip(a4, a4, a3);
	sm2_fp_sqr_hip(a5, a4);
	for (i = 1; i < 8; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a5, a5, a4);
	for (i = 0; i < 8; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a5, a5, a4);
	for (i = 0; i < 4; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a5, a5, a3);
	sm2_fp_sqr_hip(a5, a5);
	sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a5, a5, a2);
	sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a5, a5, a);
	sm2_fp_sqr_hip(a4, a5);
	sm2_fp_mul_hip(a3, a4, a1);
	sm2_fp_sqr_hip(a5, a4);
	for (i = 1; i< 31; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a4, a5, a4);
	sm2_fp_sqr_hip(a4, a4);
	sm2_fp_mul_hip(a4, a4, a);
	sm2_fp_mul_hip(a3, a4, a2);
	for (i = 0; i < 33; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a2, a5, a3);
	sm2_fp_mul_hip(a3, a2, a3);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a2, a5, a3);
	sm2_fp_mul_hip(a3, a2, a3);
	sm2_fp_mul_hip(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a2, a5, a3);
	sm2_fp_mul_hip(a3, a2, a3);
	sm2_fp_mul_hip(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a2, a5, a3);
	sm2_fp_mul_hip(a3, a2, a3);
	sm2_fp_mul_hip(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(a2, a5, a3);
	sm2_fp_mul_hip(a3, a2, a3);
	sm2_fp_mul_hip(a4, a2, a4);
	for (i = 0; i < 32; i++)
		sm2_fp_sqr_hip(a5, a5);
	sm2_fp_mul_hip(r, a4, a5);

	sm2_bn_clean(a1);
	sm2_bn_clean(a2);
	sm2_bn_clean(a3);
	sm2_bn_clean(a4);
	sm2_bn_clean(a5);
}

__device__ int sm2_fp_sqrt_hip(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN u;
	SM2_BN y; // temp result, prevent call sm2_fp_sqrt_hip(a, a)

	// r = a^((p + 1)/4) when p = 3 (mod 4)
	sm2_bn_add_hip(u, SM2_P_HIP, SM2_ONE_HIP);
	sm2_bn_rshift_hip(u, u, 2);
	sm2_fp_exp_hip(y, a, u);

	// check r^2 == a
	sm2_fp_sqr_hip(u, y);
	if (sm2_bn_cmp_hip(u, a) != 0) {
		return -1;
	}

	sm2_bn_copy(r, y);
	return 1;
}

__device__ void sm2_fn_add_hip(SM2_Fn r, const SM2_Fn a, const SM2_Fn b)
{
	sm2_bn_add_hip(r, a, b);
	if (sm2_bn_cmp_hip(r, SM2_N_HIP) >= 0) {
		sm2_bn_sub_hip(r, r, SM2_N_HIP);
	}
}

__device__ void sm2_fn_sub_hip(SM2_Fn r, const SM2_Fn a, const SM2_Fn b)
{
	if (sm2_bn_cmp_hip(a, b) >= 0) {
		sm2_bn_sub_hip(r, a, b);
	} else {
		SM2_BN t;
		sm2_bn_add_hip(t, a, SM2_N_HIP);
		sm2_bn_sub_hip(r, t, b);
	}
}

__device__ void sm2_fn_neg_hip(SM2_Fn r, const SM2_Fn a)
{
	if (sm2_bn_is_zero_hip(a)) {
		sm2_bn_copy(r, a);
	} else {
		sm2_bn_sub_hip(r, SM2_N_HIP, a);
	}
}

/* bn288 only used in barrett reduction */
__device__ int sm2_bn288_cmp_hip(const uint64_t a[9], const uint64_t b[9])
{
	int i;
	for (i = 8; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

__device__ void sm2_bn288_add_hip(uint64_t r[9], const uint64_t a[9], const uint64_t b[9])
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 9; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 8; i++) {
		r[i] &= 0xffffffff;
	}
}

__device__ void sm2_bn288_sub_hip(uint64_t ret[9], const uint64_t a[9], const uint64_t b[9])
{
	int i;
	uint64_t r[9];

	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 8; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;

	for (i = 0; i < 9; i++) {
		ret[i] = r[i];
	}
}

__device__ void sm2_fn_mul_hip(SM2_BN ret, const SM2_BN a, const SM2_BN b)
{
	SM2_BN r;
	static const uint64_t mu[9] = {
		0xf15149a0, 0x12ac6361, 0xfa323c01, 0x8dfc2096, 1, 1, 1, 1, 1,
	};

	uint64_t s[18];
	uint64_t zh[9];
	uint64_t zl[9];
	uint64_t q[9];
	uint64_t w;
	int i, j;

	/* z = a * b */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + a[i] * b[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}
	//printf("zl = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");
	//printf("zh = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zh[i]); printf("\n");

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 9; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * mu[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 8; i++) {
		q[i] = s[9 + i];
	}
	//printf("q  = "); for (i = 7; i >= 0; i--) printf("%08x", (uint32_t)q[i]); printf("\n");

	/* q = q * n mod (2^32)^9 */
	for (i = 0; i < 17; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM2_N_HIP[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}
	//printf("qn = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)q[i]); printf("\n");

	/* r = zl - q (mod (2^32)^9) */

	if (sm2_bn288_cmp_hip(zl, q)) {
		sm2_bn288_sub_hip(zl, zl, q);
	} else {
		uint64_t c[9] = {0,0,0,0,0,0,0,0,0x100000000};
		sm2_bn288_sub_hip(q, c, q);
		sm2_bn288_add_hip(zl, q, zl);
	}
	//printf("zl  = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)zl[i]); printf("\n");
	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}
	r[7] += zl[8] << 32;

	/* while r >= p do: r = r - n */
	while (sm2_bn_cmp_hip(r, SM2_N_HIP) >= 0) {
		sm2_bn_sub_hip(r, r, SM2_N_HIP);
		//printf("r-n = "); for (i = 7; i >= 0; i--) printf("%16llx ", r[i]); printf("\n");
	}
	sm2_bn_copy(ret, r);
}

__device__ void sm2_fn_mul_word_hip(SM2_Fn r, const SM2_Fn a, uint32_t b)
{
	SM2_Fn t;
	sm2_bn_set_word_hip(t, b);
	sm2_fn_mul_hip(r, a, t);
}

__device__ void sm2_fn_sqr_hip(SM2_BN r, const SM2_BN a)
{
	sm2_fn_mul_hip(r, a, a);
}

__device__ void sm2_fn_exp_hip(SM2_BN r, const SM2_BN a, const SM2_BN e)
{
	SM2_BN t;
	uint32_t w;
	int i, j;

	sm2_bn_set_word_hip(t,1);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm2_fn_sqr_hip(t, t);
			if (w & 0x80000000) {
				sm2_fn_mul_hip(t, t, a);
			}
			w <<= 1;
		}
	}
	sm2_bn_copy(r, t);
}

__device__ void sm2_fn_inv_hip(SM2_BN r, const SM2_BN a)
{
	SM2_BN e;
	sm2_bn_sub_hip(e, SM2_N_HIP, SM2_TWO_HIP);
	sm2_fn_exp_hip(r, a, e);
}


__device__ void sm2_jacobian_point_init_hip(SM2_JACOBIAN_POINT *R)
{
	memset(R, 0, sizeof(SM2_JACOBIAN_POINT));
	R->X[0] = 1;
	R->Y[0] = 1;

}

__device__ int sm2_jacobian_point_is_at_infinity_hip(const SM2_JACOBIAN_POINT *P)
{
	return sm2_bn_is_zero_hip(P->Z);
}

__device__ void sm2_jacobian_point_set_xy_hip(SM2_JACOBIAN_POINT *R, const SM2_BN x, const SM2_BN y)
{
	sm2_bn_copy(R->X, x);
	sm2_bn_copy(R->Y, y);
	sm2_bn_set_word_hip(R->Z,1);
}

__device__ void sm2_jacobian_point_get_xy_hip(const SM2_JACOBIAN_POINT *P, SM2_BN x, SM2_BN y)
{
	if (sm2_bn_is_one_hip(P->Z)) {
		sm2_bn_copy(x, P->X);
		if (y) {
			sm2_bn_copy(y, P->Y);
		}
	} else {
		SM2_BN z_inv;
		sm2_fp_inv_hip(z_inv, P->Z);
		if (y) {
			sm2_fp_mul_hip(y, P->Y, z_inv);
		}
		sm2_fp_sqr_hip(z_inv, z_inv);
		sm2_fp_mul_hip(x, P->X, z_inv);
		if (y) {
			sm2_fp_mul_hip(y, y, z_inv);
		}
	}
}

__device__ int sm2_jacobian_pointpoint_print_hip(FILE *fp, int fmt, int ind, const char *label, const SM2_JACOBIAN_POINT *P)
{
	int len = 0;
	SM2_BN x;
	SM2_BN y;

	ind += 4;

	sm2_jacobian_point_get_xy_hip(P, x, y);

	return 1;
}

__device__ int sm2_jacobian_point_is_on_curve_hip(const SM2_JACOBIAN_POINT *P)
{
	SM2_BN t0;
	SM2_BN t1;
	SM2_BN t2;

	if (sm2_bn_is_one_hip(P->Z)) {
		sm2_fp_sqr_hip(t0, P->Y);
		sm2_fp_add_hip(t0, t0, P->X);
		sm2_fp_add_hip(t0, t0, P->X);
		sm2_fp_add_hip(t0, t0, P->X);
		sm2_fp_sqr_hip(t1, P->X);
		sm2_fp_mul_hip(t1, t1, P->X);
		sm2_fp_add_hip(t1, t1, SM2_B_HIP);
	} else {
		sm2_fp_sqr_hip(t0, P->Y);
		sm2_fp_sqr_hip(t1, P->Z);
		sm2_fp_sqr_hip(t2, t1);
		sm2_fp_mul_hip(t1, t1, t2);
		sm2_fp_mul_hip(t1, t1, SM2_B_HIP);
		sm2_fp_mul_hip(t2, t2, P->X);
		sm2_fp_add_hip(t0, t0, t2);
		sm2_fp_add_hip(t0, t0, t2);
		sm2_fp_add_hip(t0, t0, t2);
		sm2_fp_sqr_hip(t2, P->X);
		sm2_fp_mul_hip(t2, t2, P->X);
		sm2_fp_add_hip(t1, t1, t2);
	}

	if (sm2_bn_cmp_hip(t0, t1) != 0) {
		return -1;
	}
	return 1;
}

__device__ void sm2_jacobian_point_neg_hip(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P)
{
	sm2_bn_copy(R->X, P->X);
	sm2_fp_neg_hip(R->Y, P->Y);
	sm2_bn_copy(R->Z, P->Z);
}

__device__ void sm2_jacobian_point_dbl_hip(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	SM2_BN T1;
	SM2_BN T2;
	SM2_BN T3;
	SM2_BN X3;
	SM2_BN Y3;
	SM2_BN Z3;
				//printf("X1 = "); print_bn(X1);
				//printf("Y1 = "); print_bn(Y1);
				//printf("Z1 = "); print_bn(Z1);

	if (sm2_jacobian_point_is_at_infinity_hip(P)) {
		sm2_jacobian_point_copy(R, P);
		return;
	}

	sm2_fp_sqr_hip(T1, Z1);		//printf("T1 = Z1^2    = "); print_bn(T1);
	sm2_fp_sub_hip(T2, X1, T1);	//printf("T2 = X1 - T1 = "); print_bn(T2);
	sm2_fp_add_hip(T1, X1, T1);	//printf("T1 = X1 + T1 = "); print_bn(T1);
	sm2_fp_mul_hip(T2, T2, T1);	//printf("T2 = T2 * T1 = "); print_bn(T2);
	sm2_fp_tri_hip(T2, T2);		//printf("T2 =  3 * T2 = "); print_bn(T2);
	sm2_fp_dbl_hip(Y3, Y1);		//printf("Y3 =  2 * Y1 = "); print_bn(Y3);
	sm2_fp_mul_hip(Z3, Y3, Z1);	//printf("Z3 = Y3 * Z1 = "); print_bn(Z3);
	sm2_fp_sqr_hip(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	sm2_fp_mul_hip(T3, Y3, X1);	//printf("T3 = Y3 * X1 = "); print_bn(T3);
	sm2_fp_sqr_hip(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	sm2_fp_div2_hip(Y3, Y3);	//printf("Y3 = Y3/2    = "); print_bn(Y3);
	sm2_fp_sqr_hip(X3, T2);		//printf("X3 = T2^2    = "); print_bn(X3);
	sm2_fp_dbl_hip(T1, T3);		//printf("T1 =  2 * T1 = "); print_bn(T1);
	sm2_fp_sub_hip(X3, X3, T1);	//printf("X3 = X3 - T1 = "); print_bn(X3);
	sm2_fp_sub_hip(T1, T3, X3);	//printf("T1 = T3 - X3 = "); print_bn(T1);
	sm2_fp_mul_hip(T1, T1, T2);	//printf("T1 = T1 * T2 = "); print_bn(T1);
	sm2_fp_sub_hip(Y3, T1, Y3);	//printf("Y3 = T1 - Y3 = "); print_bn(Y3);

	sm2_bn_copy(R->X, X3);
	sm2_bn_copy(R->Y, Y3);
	sm2_bn_copy(R->Z, Z3);

				//printf("X3 = "); print_bn(R->X);
				//printf("Y3 = "); print_bn(R->Y);
				//printf("Z3 = "); print_bn(R->Z);

}

__device__ int sm2_signature_to_der_hip(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!sig) {
		return 0;
	}
	if (asn1_integer_to_der_ex_hip(ASN1_TAG_INTEGER,sig->r, 32, NULL, &len) != 1
		|| asn1_integer_to_der_ex_hip(ASN1_TAG_INTEGER,sig->s, 32, NULL, &len) != 1
		|| asn1_header_to_der_hip(ASN1_TAG_SEQUENCE,len, out, outlen) != 1
		|| asn1_integer_to_der_ex_hip(ASN1_TAG_SEQUENCE,sig->r, 32, out, outlen) != 1
		|| asn1_integer_to_der_ex_hip(ASN1_TAG_SEQUENCE,sig->s, 32, out, outlen) != 1) {
		return -1;
	}
	return 1;
}

__device__ void sm2_jacobian_point_add_hip(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *x2 = Q->X;
	const uint64_t *y2 = Q->Y;
	SM2_BN T1;
	SM2_BN T2;
	SM2_BN T3;
	SM2_BN T4;
	SM2_BN X3;
	SM2_BN Y3;
	SM2_BN Z3;

	if (sm2_jacobian_point_is_at_infinity_hip(Q)) {
		sm2_jacobian_point_copy(R, P);
		return;
	}

	if (sm2_jacobian_point_is_at_infinity_hip(P)) {
		sm2_jacobian_point_copy(R, Q);
		return;
	}

	assert(sm2_bn_is_one_hip(Q->Z));

	sm2_fp_sqr_hip(T1, Z1);
	sm2_fp_mul_hip(T2, T1, Z1);
	sm2_fp_mul_hip(T1, T1, x2);
	sm2_fp_mul_hip(T2, T2, y2);
	sm2_fp_sub_hip(T1, T1, X1);
	sm2_fp_sub_hip(T2, T2, Y1);
	if (sm2_bn_is_zero_hip(T1)) {
		if (sm2_bn_is_zero_hip(T2)) {
			SM2_JACOBIAN_POINT _Q, *Q = &_Q;
			sm2_jacobian_point_set_xy_hip(Q, x2, y2);

			sm2_jacobian_point_dbl_hip(R, Q);
			return;
		} else {
			sm2_jacobian_point_init_hip(R);
			return;
		}
	}
	sm2_fp_mul_hip(Z3, Z1, T1);
	sm2_fp_sqr_hip(T3, T1);
	sm2_fp_mul_hip(T4, T3, T1);
	sm2_fp_mul_hip(T3, T3, X1);
	sm2_fp_dbl_hip(T1, T3);
	sm2_fp_sqr_hip(X3, T2);
	sm2_fp_sub_hip(X3, X3, T1);
	sm2_fp_sub_hip(X3, X3, T4);
	sm2_fp_sub_hip(T3, T3, X3);
	sm2_fp_mul_hip(T3, T3, T2);
	sm2_fp_mul_hip(T4, T4, Y1);
	sm2_fp_sub_hip(Y3, T3, T4);

	sm2_bn_copy(R->X, X3);
	sm2_bn_copy(R->Y, Y3);
	sm2_bn_copy(R->Z, Z3);
}

__device__ void sm2_jacobian_point_sub_hip(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q)
{
	SM2_JACOBIAN_POINT _T, *T = &_T;
	sm2_jacobian_point_neg_hip(T, Q);
	sm2_jacobian_point_add_hip(R, P, T);
}

__device__ void sm2_jacobian_point_mul_hip(SM2_JACOBIAN_POINT *R, const SM2_BN k, const SM2_JACOBIAN_POINT *P)
{
	char bits[257] = {0};
	SM2_JACOBIAN_POINT _Q, *Q = &_Q;
	SM2_JACOBIAN_POINT _T, *T = &_T;
	int i;

	// FIXME: point_add need affine, so we can not use point_add
	if (!sm2_bn_is_one_hip(P->Z)) {
		SM2_BN x;
		SM2_BN y;
		sm2_jacobian_point_get_xy_hip(P, x, y);
		sm2_jacobian_point_set_xy_hip(T, x, y);
		P = T;
	}

	sm2_jacobian_point_init_hip(Q);
	sm2_bn_to_bits_hip(k, bits);
	for (i = 0; i < 256; i++) {
		sm2_jacobian_point_dbl_hip(Q, Q);
		if (bits[i] == '1') {
			sm2_jacobian_point_add_hip(Q, Q, P);
		}
	}
	sm2_jacobian_point_copy(R, Q);
}

__device__ void sm2_jacobian_point_to_bytes_hip(const SM2_JACOBIAN_POINT *P, uint8_t out[64])
{
	SM2_BN x;
	SM2_BN y;
	sm2_jacobian_point_get_xy_hip(P, x, y);
	sm2_bn_to_bytes_hip(x, out);
	sm2_bn_to_bytes_hip(y, out + 32);
}

__device__ void sm2_jacobian_point_from_bytes_hip(SM2_JACOBIAN_POINT *P, const uint8_t in[64])
{
	sm2_bn_from_bytes_hip(P->X, in);
	sm2_bn_from_bytes_hip(P->Y, in + 32);
	sm2_bn_set_word_hip(P->Z, 1);
	/* should we check if sm2_jacobian_point_is_on_curve_hip */
}

__device__ void sm2_jacobian_point_mul_generator_hip(SM2_JACOBIAN_POINT *R, const SM2_BN k)
{
	sm2_jacobian_point_mul_hip(R, k, SM2_G_HIP);
}

/* R = t * P + s * G */
__device__ void sm2_jacobian_point_mul_sum_hip(SM2_JACOBIAN_POINT *R, const SM2_BN t, const SM2_JACOBIAN_POINT *P, const SM2_BN s)
{
	SM2_JACOBIAN_POINT _sG, *sG = &_sG;
	SM2_BN x;
	SM2_BN y;

	/* T = s * G */
	sm2_jacobian_point_mul_generator_hip(sG, s);

	// R = t * P
	sm2_jacobian_point_mul_hip(R, t, P);
	sm2_jacobian_point_get_xy_hip(R, x, y);
	sm2_jacobian_point_set_xy_hip(R, x, y);

	// R = R + T
	sm2_jacobian_point_add_hip(R, sG, R);
}

__device__ void sm2_jacobian_point_from_hex_hip(SM2_JACOBIAN_POINT *P, const char hex[64 * 2])
{
	sm2_bn_from_hex_hip(P->X, hex);
	sm2_bn_from_hex_hip(P->Y, hex + 64);
	sm2_bn_set_word_hip(P->Z,1);
}

__device__ int sm2_jacobian_point_equ_hex_hip(const SM2_JACOBIAN_POINT *P, const char hex[128])
{
	SM2_BN x;
	SM2_BN y;
	SM2_JACOBIAN_POINT _T, *T = &_T;

	sm2_jacobian_point_get_xy_hip(P, x, y);
	sm2_jacobian_point_from_hex_hip(T, hex);

	return (sm2_bn_cmp_hip(x, T->X) == 0) && (sm2_bn_cmp_hip(y, T->Y) == 0);
}

__device__ int sm2_point_is_on_curve_hip(const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT T;
	sm2_jacobian_point_from_bytes_hip(&T, (const uint8_t *)P);
	return sm2_jacobian_point_is_on_curve_hip(&T);
}

__device__ int sm2_point_is_at_infinity_hip(const SM2_POINT *P)
{
	return mem_is_zero_hip((uint8_t *)P, sizeof(SM2_POINT));
}

__device__ int sm2_point_from_x_hip(SM2_POINT *P, const uint8_t x[32], int y)
{
	SM2_BN _x, _y, _g, _z;
	sm2_bn_from_bytes_hip(_x, x);

	// g = x^3 - 3x + b = (x^2 - 3)*x + b
	sm2_fp_sqr_hip(_g, _x);
	sm2_fp_sub_hip(_g, _g, SM2_THREE_HIP);
	sm2_fp_mul_hip(_g, _g, _x);
	sm2_fp_add_hip(_g, _g, SM2_B_HIP);

	// y = g^(u + 1) mod p, u = (p - 3)/4
	sm2_fp_exp_hip(_y, _g, SM2_U_PLUS_ONE_HIP);

	// z = y^2 mod p
	sm2_fp_sqr_hip(_z, _y);
	if (sm2_bn_cmp_hip(_z, _g)) {
		return -1;
	}

	if ((y == 0x02 && sm2_bn_is_odd_hip(_y)) || ((y == 0x03) && !sm2_bn_is_odd_hip(_y))) {
		sm2_fp_neg_hip(_y, _y);
	}

	sm2_bn_to_bytes_hip(_x, P->x);
	sm2_bn_to_bytes_hip(_y, P->y);

	sm2_bn_clean(_x);
	sm2_bn_clean(_y);
	sm2_bn_clean(_g);
	sm2_bn_clean(_z);

	if (!sm2_point_is_on_curve_hip(P)) {
		return -1;
	}
	return 1;
}

__device__ int sm2_point_from_xy_hip(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32])
{
	memcpy(P->x, x, 32);
	memcpy(P->y, y, 32);
	return sm2_point_is_on_curve_hip(P);
}

__device__ int sm2_point_add_hip(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_JACOBIAN_POINT P_;
	SM2_JACOBIAN_POINT Q_;

	sm2_jacobian_point_from_bytes_hip(&P_, (uint8_t *)P);
	sm2_jacobian_point_from_bytes_hip(&Q_, (uint8_t *)Q);
	sm2_jacobian_point_add_hip(&P_, &P_, &Q_);
	sm2_jacobian_point_to_bytes_hip(&P_, (uint8_t *)R);

	return 1;
}

__device__ int sm2_point_sub_hip(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_JACOBIAN_POINT P_;
	SM2_JACOBIAN_POINT Q_;

	sm2_jacobian_point_from_bytes_hip(&P_, (uint8_t *)P);
	sm2_jacobian_point_from_bytes_hip(&Q_, (uint8_t *)Q);
	sm2_jacobian_point_sub_hip(&P_, &P_, &Q_);
	sm2_jacobian_point_to_bytes_hip(&P_, (uint8_t *)R);

	return 1;
}

__device__ int sm2_point_neg_hip(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT P_;

	sm2_jacobian_point_from_bytes_hip(&P_, (uint8_t *)P);
	sm2_jacobian_point_neg_hip(&P_, &P_);
	sm2_jacobian_point_to_bytes_hip(&P_, (uint8_t *)R);

	return 1;
}

__device__ int sm2_point_dbl_hip(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_JACOBIAN_POINT P_;

	sm2_jacobian_point_from_bytes_hip(&P_, (uint8_t *)P);
	sm2_jacobian_point_dbl_hip(&P_, &P_);
	sm2_jacobian_point_to_bytes_hip(&P_, (uint8_t *)R);

	return 1;
}

__device__ int sm2_point_mul_hip(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P)
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _P;

	sm2_bn_from_bytes_hip(_k, k);
	sm2_jacobian_point_from_bytes_hip(&_P, (uint8_t *)P);
	sm2_jacobian_point_mul_hip(&_P, _k, &_P);
	sm2_jacobian_point_to_bytes_hip(&_P, (uint8_t *)R);

	sm2_bn_clean(_k);
	return 1;
}

__device__ int sm2_point_mul_generator_hip(SM2_POINT *R, const uint8_t k[32])
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _R;

	sm2_bn_from_bytes_hip(_k, k);
	sm2_jacobian_point_mul_generator_hip(&_R, _k);
	sm2_jacobian_point_to_bytes_hip(&_R, (uint8_t *)R);

	sm2_bn_clean(_k);
	return 1;
}

__device__ int sm2_point_mul_sum_hip(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32])
{
	SM2_BN _k;
	SM2_JACOBIAN_POINT _P;
	SM2_BN _s;

	sm2_bn_from_bytes_hip(_k, k);
	sm2_jacobian_point_from_bytes_hip(&_P, (uint8_t *)P);
	sm2_bn_from_bytes_hip(_s, s);
	sm2_jacobian_point_mul_sum_hip(&_P, _k, &_P, _s);
	sm2_jacobian_point_to_bytes_hip(&_P, (uint8_t *)R);

	sm2_bn_clean(_k);
	sm2_bn_clean(_s);
	return 1;
}

__device__ void sm2_point_to_compressed_octets_hip(const SM2_POINT *P, uint8_t out[33])
{
	*out++ = (P->y[31] & 0x01) ? 0x03 : 0x02;
	memcpy(out, P->x, 32);
}

__device__ void sm2_point_to_uncompressed_octets_hip(const SM2_POINT *P, uint8_t out[65])
{
	*out++ = 0x04;
	memcpy(out, P, 64);
}

__device__ int sm2_point_from_octets_hip(SM2_POINT *P, const uint8_t *in, size_t inlen)
{
	if ((*in == 0x02 || *in == 0x03) && inlen == 33) {
		if (sm2_point_from_x_hip(P, in + 1, *in) != 1) {
			return -1;
		}
	} else if (*in == 0x04 && inlen == 65) {
		if (sm2_point_from_xy_hip(P, in + 1, in + 33) != 1) {
			return -1;
		}
	} else {
		return -1;
	}
	return 1;
}

__device__ int sm2_point_to_der_hip(const SM2_POINT *P, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	if (!P) {
		return 0;
	}
	sm2_point_to_uncompressed_octets_hip(P, octets);
	if (asn1_type_to_der_hip(ASN1_TAG_OCTET_STRING,octets,sizeof(octets),out,outlen) != 1) {
		return -1;
	}
	return 1;
}

__device__ int sm2_point_from_der_hip(SM2_POINT *P, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	if ((ret = asn1_type_from_der_hip(ASN1_TAG_OCTET_STRING,&d,&dlen,in,inlen)) != 1) {
		return ret;
	}
	if (dlen != 65) {
		return -1;
	}
	if (sm2_point_from_octets_hip(P, d, dlen) != 1) {
		return -1;
	}
	return 1;
}

int sm2_point_from_hash_hip(SM2_POINT *R, const uint8_t *data, size_t datalen)
{
	return 1;
}

