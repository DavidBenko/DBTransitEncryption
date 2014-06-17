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

- (NSString *)encryptAndBase64EncodeData:(NSData *)data base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptData:data rsaEncryptedKey:&keyData iv:iv error:error];
    *key = [keyData base64EncodedStringWithOptions:0];
    keyData = nil;
    return [encryptedData base64EncodedStringWithOptions:0];
}

- (NSString *)encryptAndBase64EncodeData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error{
	NSData *keyData = nil;
	NSData *encryptedData = [self encryptData:data withIVMixer:ivMixer rsaEncryptedKey:&keyData error:error];
    *key = [keyData base64EncodedStringWithOptions:0];
    keyData = nil;
    return [encryptedData base64EncodedStringWithOptions:0];
}

- (NSString *)encryptAndBase64EncodeString:(NSString *)string base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptString:string rsaEncryptedKey:&keyData iv:iv error:error];
    *key = [keyData base64EncodedStringWithOptions:0];
    keyData = nil;
    return [encryptedData base64EncodedStringWithOptions:0];
}

- (NSString *)encryptAndBase64EncodeString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptString:string withIVMixer:ivMixer rsaEncryptedKey:&keyData error:error];
    *key = [keyData base64EncodedStringWithOptions:0];
    keyData = nil;
    return [encryptedData base64EncodedStringWithOptions:0];
}

#pragma mark - Decryption

- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *data = [[NSData alloc]initWithBase64EncodedString:base64Data options:0];
    NSData *keyContents = [[NSData alloc]initWithBase64EncodedString:key options:0];
    return [self decryptData:data rsaEncryptedKey:keyContents iv:iv error:error];
}

- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error{
    NSData *data = [[NSData alloc]initWithBase64EncodedString:base64Data options:0];
    NSData *keyContents = [[NSData alloc]initWithBase64EncodedString:key options:0];
    return [self decryptData:data withIVSeparator:ivSeparator rsaEncryptedKey:keyContents error:error];
}

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error{
	NSData *data = [[NSData alloc]initWithBase64EncodedString:base64Data options:0];
    NSData *keyContents = [[NSData alloc]initWithBase64EncodedString:key options:0];
    return [self decryptString:data rsaEncryptedKey:keyContents iv:iv error:error];
}

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error{
    NSData *data = [[NSData alloc]initWithBase64EncodedString:base64Data options:0];
    NSData *keyContents = [[NSData alloc]initWithBase64EncodedString:key options:0];
    return [self decryptString:data withIVSeparator:ivSeparator rsaEncryptedKey:keyContents error:error];
}
@end
