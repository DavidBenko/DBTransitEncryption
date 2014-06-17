//
//  DBTransitEncryptor+Base64.h
//  Pods
//
//  Created by David Benko on 6/16/14.
//
//

#import "DBTransitEncryptor.h"

@interface DBTransitEncryptor (Base64)

#pragma mark - Encryption
/**
 * Generates symmetric key and iv, symmetrically encrypts data, RSA encrypts symmetric key
 *
 * @param data The data to be encrypted
 * @param key The RSA-encrypted, randomly generated, symmetric key, base64 encoded
 * @param iv The randomly generated IV
 * @param error Errors will be filled here
 * @return the encrypted data as a base64 encoded string
 */
- (NSString *)encryptAndBase64EncodeData:(NSData *)data base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts data, RSA encrypts symmetric key
 * The IVMixerBlock is fired after the symmetric data encryption and before the symmetric key is encrypted.
 * Use the IVMixerBlock to mix the IV with either the data or key. 
 * If passed here, the IVMixerBlock will override the ivMixer property, but only for this call
 *
 * @param data The data to be encrypted
 * @param ivMixer Block to mix the IV with key or data
 * @param key The RSA-encrypted, randomly generated, symmetric key, base64 encoded
 * @param error Errors will be filled here
 * @return the encrypted data as a base64 encoded string
 */
- (NSString *)encryptAndBase64EncodeData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts string, RSA encrypts symmetric key
 *
 * @param string The string to be encrypted
 * @param key The RSA-encrypted, randomly generated, symmetric key, base64 encoded
 * @param iv The randomly generated IV
 * @param error Errors will be filled here
 * @return the encrypted data as a base64 encoded string
 */
- (NSString *)encryptAndBase64EncodeString:(NSString *)string base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error;

/**
 * Generates symmetric key and iv, symmetrically encrypts string, RSA encrypts symmetric key
 * The IVMixerBlock is fired after the symmetric data encryption and before the symmetric key is encrypted.
 * Use the IVMixerBlock to mix the IV with either the data or key.
 * If passed here, the IVMixerBlock will override the ivMixer property, but only for this call
 *
 * @param string The string to be encrypted
 * @param ivMixer Block to mix the IV with key or data
 * @param key The RSA-encrypted, randomly generated, symmetric key, base64 encoded
 * @param error Errors will be filled here
 * @return the encrypted data as a base64 encoded string
 */
- (NSString *)encryptAndBase64EncodeString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error;

#pragma mark - Decryption


/**
 * Decrypts data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 *
 * @param base64Data The data to be decrypted as a base64 encoded string
 * @param key The RSA-encrypted symmetric key, base64 encoded
 * @param iv The IV
 * @param error Errors will be filled here
 * @return the decrypted data
 */
- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error;


/**
 * Decrypts data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 * The IVSeparatorBlock should undo the IVMixerBlock run during encryption
 *
 * @param base64Data The data to be decrypted as a base64 encoded string
 * @param ivSeparator The IVSeparatorBlock to retrieve the IV from the key or data
 * @param key The RSA-encrypted symmetric key, base64 encoded
 * @param error Errors will be filled here
 * @return the decrypted data
 */
- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error;

/**

 * Decrypts string from encrypted, base64 encoded, data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 *
 * @param base64Data The data to be decrypted as a base64 encoded string
 * @param key The RSA-encrypted symmetric key, base64 encoded
 * @param iv The IV
 * @param error Errors will be filled here
 * @return the decrypted string
 */
- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error;

/**
 * Decrypts string from encrypted, base64 encoded, data. The private key must be set for this method to function.
 * @see setPrivateKey:withPassphrase:
 * The IVSeparatorBlock should undo the IVMixerBlock run during encryption
 *
 * @param base64Data The data to be decrypted as a base64 encoded string
 * @param ivSeparator The IVSeparatorBlock to retrieve the IV from the key or data
 * @param key The RSA-encrypted symmetric key, base64 encoded
 * @param error Errors will be filled here
 * @return the decrypted string
 */
- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error;
@end
