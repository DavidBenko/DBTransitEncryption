//
//  ObjectiveTLS.h
//  DBTransitEncryption
//
//  Created by David Benko on 5/9/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ObjectiveTLS : NSObject

/*
 *
 * Init with either:
 * - X509 RSA Public Key Path
 * - Base64 encoded X509 RSA Public Key Data
 *
 */
- (ObjectiveTLS *)initWithX509PublicKeyData:(NSData *)base64KeyData;
- (ObjectiveTLS *)initWithX509PublicKey:(NSString *)publicKeyPath;

/*
 *
 * AES Encrypt NSData or NSString
 *
 * Returns Encrypted NSData
 * Sets Pointer to RSA-Encrypted AES Key
 * Sets Pointer to Randomly Generated IV
 * Sets Pointer to Randomly Generted Salt
 * Sets Pointer to NSError
 *
 */
- (NSData *)aesEncryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv salt:(NSData **)salt error:(NSError **)error;
- (NSData *)aesEncryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv salt:(NSData **)salt error:(NSError **)error;

@end
