//
//  DBTransitEncryptor+NSString.m
//  Pods
//
//  Created by David Benko on 6/16/14.
//
//

#import "DBTransitEncryptor+NSString.h"

@implementation DBTransitEncryptor (NSString)

#pragma mark - Encryption
- (NSData *)encryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *dataToEncrypt = [string dataUsingEncoding:self.encryptorStringEncoding];
    return [self encryptData:dataToEncrypt rsaEncryptedKey:key iv:iv error:error];
}

- (NSData *)encryptString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer rsaEncryptedKey:(NSData **)key error:(NSError **)error {
    NSData *dataToEncrypt = [string dataUsingEncoding:self.encryptorStringEncoding];
    return [self encryptData:dataToEncrypt withIVMixer:ivMixer rsaEncryptedKey:key error:error];
}

#pragma mark - Decryption

- (NSString *)decryptString:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
	NSData *decryptedData = [self decryptData:data rsaEncryptedKey:key iv:iv error:error];
	return [[NSString alloc]initWithData:decryptedData encoding:self.encryptorStringEncoding];
}

- (NSString *)decryptString:(NSData *)data withIVSeparator:(IVSeparatorBlock)ivSeparator rsaEncryptedKey:(NSData *)key error:(NSError **)error{
    NSData *decryptedData = [self decryptData:data withIVSeparator:ivSeparator rsaEncryptedKey:key error:error];
    return [[NSString alloc]initWithData:decryptedData encoding:self.encryptorStringEncoding];
}

@end
