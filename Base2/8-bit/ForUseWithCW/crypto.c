/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Dirk Klose
 * Riley Myers (william.myers@inl.gov)
 * William Unger (williamunger@u.boisestate.edu)
 */

#include "crypto.h"
#include "boxes.h"
#include <stdint.h>
//#include <stdio.h>

#define True  1
#define False 0
#define numRounds64 28
#define bitToByte(num) (uint8_t) ((num)/8)


uint8_t newKeyScheduler64(uint8_t keyState[16], uint8_t subKeys[28][8])
{
    uint8_t i;
    uint8_t j;
    uint8_t k;
    uint8_t u[2];
    uint8_t v[2];
    uint8_t keyStateUpdated[16];
    
    for(i = 0; i < numRounds64; i++)  //loops though 28 rounds and genetares a 64-bit round key for each round
    {
        if(i == 0)
        {
            //printf("inital key state\n");
            int l;
            for(l = 0; l < 16; l++)
            {
               // printf("%02hhx", keyState[l]);
            }
        }
        //printf("I value is %d\n", i);
        v[0] = keyState[0];
        v[1] = keyState[1];
        u[0] = keyState[2];
        u[1] = keyState[3];
        
        for(j = 0; j < 8; j++)
        {
            subKeys[i][j] = (uint8_t) 0;
        }
        for(j = 0; j < 16; j++)
        {
            //printf("%i\n",bitToByte(4*j+1));
            subKeys[i][bitToByte(4*j+1)] |= (uint8_t) (((u[bitToByte(j)] >> (j%8)) & 0x01) << ( (4*j+1)%8));
            subKeys[i][bitToByte(4*j)] |= (uint8_t) (((v[bitToByte(j)] >> (j%8)) & 0x01) << ( (4*j)%8));
            
            
        }
        for(k = 0; k < 6; k++)//Constants added to sub-keys
            {
                subKeys[i][bitToByte(ConstantsLocation[k])] |= (uint8_t) (((Constants[i] >> k) & 0x01) << (ConstantsLocation[k] % 8));
            }
            
            subKeys[i][7] |= (uint8_t) 0x80; //Adding the always on bit
        for(j = 0; j < 12; j++)
        {
            keyStateUpdated[j] = keyState[j+4];
        }
        keyStateUpdated[12] = (uint8_t) (keyState[1] >> 4) | (keyState[0] << 4);
        keyStateUpdated[13] = (uint8_t) (keyState[0] >> 4) | (keyState[1] << 4);
        keyStateUpdated[14] =  (uint8_t) (keyState[2] >> 2) | (keyState[3] << 6);
        keyStateUpdated[15] = (uint8_t) (keyState[3] >> 2) | (keyState[2] << 6);
        
        for(j = 0; j < 16; j++)
        {
            keyState[j] = keyStateUpdated[j];
        }
    }
    
    return 0;
}







//----------------------------------
// Encryption
//----------------------------------

// These encrypt the plaintext using a pregenerated subkey array
uint8_t encrypt64(uint8_t textIn[8], uint8_t subKeys[28][8])
{
    uint8_t i;
    uint8_t j;
    uint8_t left;
    uint8_t right;
	uint8_t left2;
	uint8_t right2;
    uint8_t pLayerTemp[8];
    uint8_t tempBit;
    uint8_t pVal;
    for(i = 0; i < numRounds64; i++)
    {
        
        for(j = 0; j < 8; j++) //SBox layer
        {
			left2 = 0;
			right2 = 0;
            left = textIn[j] >> 4;
            left2 = Sbox[left];
            right = textIn[j] & 0x0f;
            right2 = Sbox[right];
            textIn[j] = (left2 << 4) | right2;
        }
        
        for(j = 0; j < 8; j++)//pLayer initization
        {
            pLayerTemp[j] = 0;
        }
        
        for(j = 0; j < 64; j++)//pLayer code
        {
            tempBit = (textIn[bitToByte(j)] >> (j%8)) & 0x01;
            pVal = Pbox[j];
            pLayerTemp[bitToByte(pVal)] |= (tempBit << (pVal % 8));
        }
        
        for(j = 0; j < 8; j++)//putting pLayer Resutls in the textIn array
        {
            textIn[j] = pLayerTemp[j];
        }
        for(j = 0; j < 8; j++)
        {
            textIn[j] = textIn[j] ^ subKeys[i][j]; //Adding the round key
        }
        
    }
    return 0;
}

