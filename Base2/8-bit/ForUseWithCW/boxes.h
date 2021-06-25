/**
 * Sbox (and Pbox) implementations for the GIFT cypher utilizing 8-bit native
 * data types.
 *
 * Riley Myers (william.myers@inl.gov)
 * 07.15.19
 *
 * Based on work done by Dirk Klose and Embedded Security Group of
 * Ruhr-Universitaet Bochum, Germany.
 **/

#pragma once
#include <stdint.h>

// GIFT ?
const uint8_t Sbox[16] = { 0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                           0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe };

const uint8_t SboxInv[16] = { 0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb,
                              0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5 };
							  

// PRESENT

//const uint8_t Sbox[16]    = { 0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
//                           0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2 };
//const uint8_t SboxInv[16] = { 0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd,
//                              0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa };
                              
//Piccolo
//const uint8_t Sbox[16]    = { 0xe, 0x4, 0xb, 0x2, 0x3, 0x8, 0x0, 0x9,
//                           0x1, 0xa, 0x7, 0xf, 0x6, 0xc, 0x5, 0xd };
						   
//S(x) = x + 1 mod 16
//const uint8_t Sbox[16]    = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
//                           0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0 };

//S(X) = -x mod 16
//const uint8_t Sbox[16] = {0x0,0xf,0xe, 0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1}; 
	
//Random 1.1	
//const uint8_t Sbox[16] = {0x0,0xe,0x7,0x6,0x4,0x5,0x2,0x1,0x3,0xf,0xa,0xb,0x8,0x9,0xc,0xd}; 					   						   
	
//Random 1.2
//const uint8_t Sbox[16] = {0x5,0x1,0x7,0x6,0x4,0x0,0x2,0xe,0x3,0xf,0xb,0xa,0x8,0x9,0xc,0xd};	

//GIFTLike
//const uint8_t Sbox[16] = {0,1,2,3,4,5,9,11,6,15,7,13,8,10,14,12};

//PRESENTLike
//const uint8_t Sbox[16] = {0,1,2,3,4,5,8,14,6,11,15,13,10,9,7,12};

//PICCOLOLike
//const uint8_t Sbox[16] = {0,1,2,3,4,5,9,15,6,7,10,12,14,8,13,11};

//S1-2Like
//const uint8_t Sbox[16] = {0, 1, 2, 3, 4, 5, 6, 15, 7, 8, 9, 11, 10, 13, 14, 12};

//XPlus1Like
//const uint8_t Sbox[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 12};

//S1-1Like
//const uint8_t Sbox[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 15, 12, 10};

//MinusXLike
//const uint8_t Sbox[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 12};

//NL2Num2
//const uint8_t Sbox[16] = {5,4,6,9,8,0xf,0xa,0xb,0,2,3,0xc,0xd,1,0xe,7};

//NL2Num3
//const uint8_t Sbox[16] = {0xf,4,5,6,0xa,0xb,0,2,1,3,0xd,0xe,9,7,8,0xc};

//NL2Num4
//const uint8_t Sbox[16] = {0,0xa,0xb,0xf,9,8,7,4,5,6,0xc,0xe,0xd,1,3,2};

//B4-1 
//const uint8_t Sbox[16] = {3,14,12,0,8,13,5,2,1,4,15,9,6,11,10,7};

//B4-2
//const uint8_t Sbox[16] = {9,6,4,10,8,15,3,5,7,0,14,1,2,12,13,11};
	
//B4-3
//const uint8_t Sbox[16] = {6,8,9,5,11,13,0,2,4,3,15,10,1,14,12,7};

//B4-4
//const uint8_t Sbox[16] = {6,2,13,8,9,15,0,3,1,12,11,7,10,5,4,14};

//B4-5
//const uint8_t Sbox[16] = {3,12,13,0,2,15,8,6,4,10,14,1,9,5,7,11};

//B4-6
//const uint8_t Sbox[16] = {12,2,4,9,11,7,1,14,3,5,15,10,0,8,6,13};

//B4-7
//const uint8_t Sbox[16] = {9,14,1,4,2,7,12,11,6,0,15,3,5,8,10,13};

//B4-8
//const uint8_t Sbox[16] = {12,8,1,6,3,15,10,5,7,2,11,13,0,9,4,14};


//B5-1
//const uint8_t Sbox[16] = {12,6,1,8,2,9,14,5,13,3,11,4,0,15,7,10};

//B5-2
//const uint8_t Sbox[16] = {6,12,7,9,8,3,0,15,1,2,11,4,14,5,13,10};

//B5-3
//const uint8_t Sbox[16] = {9,11,12,6,2,7,1,8,4,0,3,15,13,14,10,5};

//B5-4
//const uint8_t Sbox[16] = {3,11,4,0,8,13,7,14,6,12,9,15,1,2,10,5};

//B5-5
//const uint8_t Sbox[16] = {9,2,4,11,3,12,8,5,13,0,14,7,6,15,1,10};

//B5-6
//const uint8_t Sbox[16] = {6,8,1,7,14,13,0,11,3,4,12,10,9,2,15,5};

//B5-7
//const uint8_t Sbox[16] = {3,8,7,0,9,6,12,15,4,11,14,13,2,5,1,10};

//B5-8
//const uint8_t Sbox[16] = {12,2,9,4,14,7,3,8,1,13,6,10,0,11,15,5};



	   
const uint8_t Constants[48] = // Added to use GIFT structure
  { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c,
    0x39, 0x33, 0x27, 0x0e, 0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38, 0x31, 0x23, 0x06, 0x0d,
    0x1b, 0x36, 0x2d, 0x1a, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04 };

const uint8_t ConstantsLocation[6] = { 3, 7, 11, 15, 19, 23 };

const uint8_t Pbox[64] = { 0,  17, 34, 51, 48, 1,  18, 35, 32, 49, 2,  19, 16,
                           33, 50, 3,  4,  21, 38, 55, 52, 5,  22, 39, 36, 53,
                           6,  23, 20, 37, 54, 7,  8,  25, 42, 59, 56, 9,  26,
                           43, 40, 57, 10, 27, 24, 41, 58, 11, 12, 29, 46, 63,
                           60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15 };

