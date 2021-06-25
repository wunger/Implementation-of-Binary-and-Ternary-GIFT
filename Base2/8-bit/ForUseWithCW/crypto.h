/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Dirk Klose
 * Riley Myers (william.myers@inl.gov)
 * William Unger (williamunger@u.boisestate.edu)
 */

#pragma once
#include <stdint.h>

#define KEY_LENGTH 16
#define DEFAULT_KEY                                                            \
    {                                                                          \
        0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, 0xab, 0xab, 0x12,      \
          0x34, 0xdf, 0xec, 0x2f, 0x3c                                         \
    }

//----------------------------------
// Function prototypes
//----------------------------------

//----------------------------------
// Encryption
//----------------------------------
// All of these functions take the plaintext as the first argument, and modify
// it in-place.

// These encrypt the plaintext using a pregenerated subkey array, optimizing for
// speed (TODO!)
uint8_t encrypt64(uint8_t textIn[8], uint8_t subKeys[28][8]);  //Use this one for encryption with 8-bit native data type




//----------------------------------
// Decryption (TODO)
//----------------------------------


//----------------------------------
// Key scheduling 
//----------------------------------

uint8_t newKeyScheduler64(uint8_t keyState[16], uint8_t subKeys[28][8]);

