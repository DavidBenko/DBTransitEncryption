//
//  DBTransitEncryption.h
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
#import <CommonCrypto/CommonCryptor.h>

typedef void (^IVMixerBlock) (NSData **data,NSData **key, NSData *iv);
typedef NSData* (^IVSeparatorBlock) (NSData **data, NSData **key);

@interface DBTransitEncryption : NSObject

@property (nonatomic, assign) NSUInteger rsaKeySize;                        // RSA key size in bits
@property (nonatomic, assign) SecPadding rsaPadding;                        // RSA padding
@property (nonatomic, assign) CCAlgorithm encryptorAlgorithm;               // Data payload encryption algorithm
@property (nonatomic, assign) CCOptions encryptorAlgorithmOptions;          // Options (padding) for data payload encryptor
@property (nonatomic, assign) NSUInteger encryptorAlgorithmKeySize;         // Size of generated symmetric key
@property (nonatomic, assign) NSUInteger encryptorAlgorithmBlockSize;       // Block size of data payload encryption algorithm
@property (nonatomic, assign) NSUInteger encryptorAlgorithmIVSize;          // Size of generated initialization vector
@property (nonatomic, assign) NSStringEncoding encryptorStringEncoding;     // String encoding for encrypted/decrypted strings
@property (readwrite, copy) IVMixerBlock ivMixer;                           // Block to mix IV with key or data
@property (readwrite, copy) IVSeparatorBlock ivSeparator;                   // Block to separate IV from key or data

#pragma mark - Init

/** 
 * Initializes a new ObjectiveTLS object with the contents of a X.509 RSA public key
 *
 * @param base64KeyData The contents of the public key
 * @return new ObjectiveTLS instance
 */
- (DBTransitEncryption *)initWithX509PublicKeyData:(NSData *)base64KeyData;

/**
 * Initializes a new ObjectiveTLS object with the contents of a X.509 RSA public key at a given path
 *
 * @param publicKeyPath The file path of the public key
 * @return new ObjectiveTLS instance
 */
- (DBTransitEncryption *)initWithX509PublicKey:(NSString *)publicKeyPath;

#pragma mark - PKCS#12 RSA Private Key (.p12)

/**
 * Sets the RSA private key for decryption
 *
 * @param privateKeyPath The file path of the private key (.p12)
 * @param password The password to read the private key (nil for no password)
 * @return a boolean representing the success of the operation
 */
-(BOOL)setPrivateKey:(NSString *)privateKeyPath withPassphrase:(NSString *)password;


#pragma mark - Public Encryption Methods

/**
 * Generates symmetric key and iv, symmetrically encrypts data, RSA encrypts symmetric key
 *
 * @param data The data to be encrypted
 * @param key The RSA-encrypted, randomly generated, symmetric key
 * @param iv The randomly generated IV
 * @param error Errors will be filled here
 * @return the encrypted data
 */
- (NSData *)encryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts string, RSA encrypts symmetric key
 *
 * @param string The string to be encrypted
 * @param key The RSA-encrypted, randomly generated, symmetric key
 * @param iv The randomly generated IV
 * @param error Errors will be filled here
 * @return the encrypted data
 */
- (NSData *)encryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts data, RSA encrypts symmetric key
 * The IVMixerBlock is fired after the symmetric data encryption and before the symmetric key is encrypted.
 * Use the IVMixerBlock to mix the IV with either the data or key. 
 * If passed here, the IVMixerBlock will override the ivMixer property, but only for this call
 *
 * @param data The data to be encrypted
 * @param ivMixer Block to mix the IV with key or data
 * @param key The RSA-encrypted, randomly generated, symmetric key
 * @param error Errors will be filled here
 * @return the encrypted data
 */
- (NSData *)encryptData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer rsaEncryptedKey:(NSData **)key error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts string, RSA encrypts symmetric key
 * The IVMixerBlock is fired after the symmetric data encryption and before the symmetric key is encrypted.
 * Use the IVMixerBlock to mix the IV with either the data or key.
 * If passed here, the IVMixerBlock will override the ivMixer property, but only for this call
 *
 * @param string The string to be encrypted
 * @param ivMixer Block to mix the IV with key or data
 * @param key The RSA-encrypted, randomly generated, symmetric key
 * @param error Errors will be filled here
 * @return the encrypted data
 */
- (NSData *)encryptString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer rsaEncryptedKey:(NSData **)key error:(NSError **)error;

#pragma mark - Public Decryption Methods

/**
 * Decrypts data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 *
 * @param data The data to be decrypted
 * @param key The RSA-encrypted symmetric key
 * @param iv The IV
 * @param error Errors will be filled here
 * @return the decrypted data
 */
- (NSData *)decryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error;

/**
 * Decrypts string from encrypted data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 *
 * @param data The data to be decrypted
 * @param key The RSA-encrypted symmetric key
 * @param iv The IV
 * @param error Errors will be filled here
 * @return the decrypted string
 */
- (NSString *)decryptString:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error;

/**
 * Decrypts data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 * The IVSeparatorBlock should undo the IVMixerBlock run during encryption
 *
 * @param data The data to be decrypted
 * @param ivSeparator The IVSeparatorBlock to retrieve the IV from the key or data
 * @param key The RSA-encrypted symmetric key
 * @param error Errors will be filled here
 * @return the decrypted data
 */
- (NSData *)decryptData:(NSData *)data withIVSeparator:(IVSeparatorBlock)ivSeparator rsaEncryptedKey:(NSData *)key error:(NSError **)error;

/**
 * Decrypts string from encrypted data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 * The IVSeparatorBlock should undo the IVMixerBlock run during encryption
 *
 * @param data The data to be decrypted
 * @param ivSeparator The IVSeparatorBlock to retrieve the IV from the key or data
 * @param key The RSA-encrypted symmetric key
 * @param error Errors will be filled here
 * @return the decrypted string
 */
- (NSString *)decryptString:(NSData *)data withIVSeparator:(IVSeparatorBlock)ivSeparator rsaEncryptedKey:(NSData *)key error:(NSError **)error;

@end
