//
//  ObjectiveTLS.h
//  DBTransitEncryption
//
//  Created by David Benko on 5/9/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//
// Thanks to:
// http://robnapier.net/aes-commoncrypto/   AES Encryption Algorithms
// https://github.com/xjunior/XRSA          RSA Encryption Algorithms
//

#import <Foundation/Foundation.h>

@interface ObjectiveTLS : NSObject

/*
 *
 * Init with either:
 * - DER-encoded X509 RSA Public Key Path (.der)
 * - Base64 encoded X509 RSA Public Key Data
 *
 */
- (ObjectiveTLS *)initWithX509PublicKeyData:(NSData *)base64KeyData;
- (ObjectiveTLS *)initWithX509PublicKey:(NSString *)publicKeyPath;


/*
 *
 * (Optional) Set Private Key
 * - PKCS#12 RSA Private Key (.p12)
 *
 * Returns BOOL - True or False based on success of private key trust
 *
 */

-(BOOL)setPrivateKey:(NSString *)privateKeyPath withPassphrase:(NSString *)password;

/*
 *
 * AES Encrypt NSData or NSString
 *
 * Returns Encrypted NSData
 * Sets Pointer to RSA-Encrypted AES Key
 * Sets Pointer to Randomly Generated IV
 * Sets Pointer to NSError
 *
 */
- (NSData *)aesEncryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error;
- (NSData *)aesEncryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error;

/*
 *
 * AES Decrypt NSData
 *
 * Returns Decrypted NSData or NSString
 * Sets Pointer to NSError
 *
 */
- (NSData *)aesDecryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error;
- (NSString *)aesStringDecryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error;

@end
