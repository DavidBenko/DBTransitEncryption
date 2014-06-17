//
//  DBTransitEncryptor+NSString.h
//  Pods
//
//  Created by David Benko on 6/16/14.
//
//

#import "DBTransitEncryptor.h"

@interface DBTransitEncryptor (NSString)
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
