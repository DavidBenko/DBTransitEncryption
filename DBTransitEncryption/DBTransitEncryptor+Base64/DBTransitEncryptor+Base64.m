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

#pragma mark - Base64 Handling

NSString* base64EncodeData(NSData* data){
    if ([data respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        return [data base64EncodedStringWithOptions:0];
    }
    else{
        return [data base64Encoding];
    }
}

NSData* base64DecodeData(NSString *base64){
    if ([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)]) {
        return [[NSData alloc]initWithBase64EncodedString:base64 options:0];
    }
    else {
        return [[NSData alloc]initWithBase64Encoding:base64];
    }
}

#pragma mark - Encryption

- (NSString *)encryptAndBase64EncodeData:(NSData *)data base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptData:data rsaEncryptedKey:&keyData iv:iv error:error];
    *key = base64EncodeData(keyData);
    keyData = nil;
    return base64EncodeData(encryptedData);
}

- (NSString *)encryptAndBase64EncodeData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error{
	NSData *keyData = nil;
	NSData *encryptedData = [self encryptData:data withIVMixer:ivMixer rsaEncryptedKey:&keyData error:error];
    *key = base64EncodeData(keyData);
    keyData = nil;
    return base64EncodeData(encryptedData);
}

- (NSString *)encryptAndBase64EncodeString:(NSString *)string base64RsaEncryptedKey:(NSString **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptString:string rsaEncryptedKey:&keyData iv:iv error:error];
    *key = base64EncodeData(keyData);
    keyData = nil;
    return base64EncodeData(encryptedData);
}

- (NSString *)encryptAndBase64EncodeString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer base64RsaEncryptedKey:(NSString **)key error:(NSError **)error{
    NSData *keyData = nil;
	NSData *encryptedData = [self encryptString:string withIVMixer:ivMixer rsaEncryptedKey:&keyData error:error];
    *key = base64EncodeData(keyData);
    keyData = nil;
    return base64EncodeData(encryptedData);
}

#pragma mark - Decryption

- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *data = base64DecodeData(base64Data);
    NSData *keyContents = base64DecodeData(key);
    return [self decryptData:data rsaEncryptedKey:keyContents iv:iv error:error];
}

- (NSData *)base64decodeAndDecryptData:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error{
    NSData *data = base64DecodeData(base64Data);
    NSData *keyContents = base64DecodeData(key);
    return [self decryptData:data withIVSeparator:ivSeparator rsaEncryptedKey:keyContents error:error];
}

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data base64RsaEncryptedKey:(NSString *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *data = base64DecodeData(base64Data);
    NSData *keyContents = base64DecodeData(key);
    return [self decryptString:data rsaEncryptedKey:keyContents iv:iv error:error];
}

- (NSString *)base64decodeAndDecryptString:(NSString *)base64Data withIVSeparator:(IVSeparatorBlock)ivSeparator base64RsaEncryptedKey:(NSString *)key error:(NSError **)error{
    NSData *data = base64DecodeData(base64Data);
    NSData *keyContents = base64DecodeData(key);
    return [self decryptString:data withIVSeparator:ivSeparator rsaEncryptedKey:keyContents error:error];
}
@end
