//
//  DBTransitEncryptor+Base64.m
//  Pods
//
//  Created by David Benko on 6/16/14.
//
//

#import "DBTransitEncryptor+Base64.h"
#import "DBTransitEncryptor+NSString.h"

@implementation DBTransitEncryptor (Base64)
#pragma mark - Encryption

- (NSString *)encryptAndBase64EncodeData:(NSData *)data base64RsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
	
}

- (NSString *)encryptAndBase64EncodeData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSData **)key error:(NSError **)error{
	
}

- (NSString *)encryptAndBase64EncodeString:(NSString *)string base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error{
	
}

- (NSData *)encryptAndBase64EncodeString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error{
	
}

#pragma mark - Decryption

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data base64RsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
	
}

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSData *)key error:(NSError **)error{
	
}
@end
