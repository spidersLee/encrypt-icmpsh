#ifndef _AES_H
#define _AES_H

/****************************************************************************
*  Include Files                       
*****************************************************************************/


/*****************************************************************************
*  Define                              
******************************************************************************/

#define AES_KEY_LENGTH	128


#define AES_MODE_ECB	0				
#define AES_MODE_CBC	1				
#define AES_MODE		AES_MODE_ECB	

/*****************************************************************************
*  Functions Define                    
******************************************************************************/


extern void AES_Init(const void *pKey);


void AES_Encrypt(const unsigned char *pPlainText, unsigned char *pCipherText,
                 unsigned int nDataLen, const unsigned char *pIV);



void AES_Decrypt(unsigned char *pPlainText, const unsigned char *pCipherText,
                 unsigned int nDataLen, const unsigned char *pIV);


unsigned int AES_add_pkcs7Padding(unsigned char *input, unsigned int len);


unsigned int AES_delete_pkcs7Padding(unsigned char *input, unsigned int len);
#endif  /* _AES_H */
