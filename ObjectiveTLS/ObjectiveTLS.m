//
//  ObjectiveTLS.m
//  DBTransitEncryption
//
//  Created by David Benko on 5/9/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//
// Thanks to:
// http://robnapier.net/aes-commoncrypto/   AES Encryption Algorithms
// https://github.com/xjunior/XRSA          RSA Encryption Algorithms
//

#import "ObjectiveTLS.h"
#import <CommonCrypto/CommonCryptor.h>

@interface ObjectiveTLS (){
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    SecCertificateRef certificate;
    SecPolicyRef policy;
    SecTrustRef trust;
    size_t maxPlainLen;
}
@end

@implementation ObjectiveTLS

static const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
static const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
static const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
static const NSUInteger kAlgorithmIVSize = kCCBlockSizeAES128;
static const NSStringEncoding kStringEncoding = NSUTF8StringEncoding;
static NSString * const kObjectiveTLSErrorDomain = @"com.davidbenko.objectivetls";


#pragma mark - Init

- (ObjectiveTLS *)initWithX509PublicKeyData:(NSData *)base64KeyData {
    self = [super init];
    
    if (self) {
        if (base64KeyData == nil) {
            return nil;
        }
        
        certificate = SecCertificateCreateWithData(kCFAllocatorDefault, ( __bridge CFDataRef) base64KeyData);
        if (certificate == nil) {
            NSLog(@"Can not read certificate from data");
            return nil;
        }
        
        policy = SecPolicyCreateBasicX509();
        OSStatus returnCode = SecTrustCreateWithCertificates(certificate, policy, &trust);
        if (returnCode != 0) {
            NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)returnCode);
            return nil;
        }
        
        SecTrustResultType trustResultType;
        returnCode = SecTrustEvaluate(trust, &trustResultType);
        if (returnCode != 0) {
            return nil;
        }
        
        publicKey = SecTrustCopyPublicKey(trust);
        if (publicKey == nil) {
            NSLog(@"SecTrustCopyPublicKey fail");
            return nil;
        }
        
        maxPlainLen = SecKeyGetBlockSize(publicKey) - 12;
    }
    
    return self;
}

- (ObjectiveTLS *)initWithX509PublicKey:(NSString *)publicKeyPath {
    if (publicKeyPath == nil) {
        NSLog(@"Can not find %@", publicKeyPath);
        return nil;
    }
    
    NSData *publicKeyFileContent = [NSData dataWithContentsOfFile:publicKeyPath];
    return [self initWithX509PublicKeyData:publicKeyFileContent];
}

#pragma mark - Private Key (.p12)
-(BOOL)setPrivateKey:(NSString *)privateKeyPath withPassphrase:(NSString *)password{
    NSData *pkcs12key = [NSData dataWithContentsOfFile:privateKeyPath];
    NSDictionary* options = NULL;
    CFArrayRef importedItems = NULL;
    
    if (password) {
        options = [NSDictionary dictionaryWithObjectsAndKeys: password, kSecImportExportPassphrase, nil];
    }
    
    OSStatus returnCode = SecPKCS12Import((__bridge CFDataRef) pkcs12key,
                                          (__bridge CFDictionaryRef) options,
                                          &importedItems);
    
    if (returnCode != 0) {
        NSLog(@"SecPKCS12Import fail");
        return FALSE;
    }
    
    NSDictionary* item = (NSDictionary*) CFArrayGetValueAtIndex(importedItems, 0);
    SecIdentityRef  identity = (__bridge SecIdentityRef) [item objectForKey:(__bridge NSString *) kSecImportItemIdentity];
    SecIdentityCopyPrivateKey(identity, &privateKey);
    if (privateKey == nil) {
        NSLog(@"SecIdentityCopyPrivateKey fail");
        return FALSE;
    }
    
    return TRUE;
}

#pragma mark - RSA Encryption
- (NSData *) RSAEncryptData:(NSData *)content {
    
    NSAssert(publicKey != nil,@"Public key can not be nil");
    
    size_t plainLen = [content length];
    if (plainLen > maxPlainLen) {
        NSLog(@"content(%ld) is too long, must < %ld", plainLen, maxPlainLen);
        return nil;
    }
    
    void *plain = malloc(plainLen);
    [content getBytes:plain
               length:plainLen];
    
    size_t cipherLen = 128; // currently RSA key length is set to 128 bytes
    void *cipher = malloc(cipherLen);
    
    OSStatus returnCode = SecKeyEncrypt(publicKey, kSecPaddingPKCS1, plain,
                                        plainLen, cipher, &cipherLen);
    
    NSData *result = nil;
    if (returnCode != 0) {
        NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)returnCode);
    }
    else {
        result = [NSData dataWithBytes:cipher
                                length:cipherLen];
    }
    
    free(plain);
    free(cipher);
    
    return result;
}

#pragma mark - RSA Decryption
-(NSData *)RSADecryptData:(NSData *)content{
    
    NSAssert(publicKey != nil,@"Private key can not be nil");
    
    size_t cipherLen = [content length];
    void *cipher = malloc(cipherLen);
    [content getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(privateKey) - 12;
    void *plain = malloc(plainLen);
    
    OSStatus returnCode = SecKeyDecrypt(privateKey, kSecPaddingPKCS1, cipher,
                                        cipherLen, plain, &plainLen);
    
    NSData *result = nil;
    if (returnCode != 0) {
        NSLog(@"SecKeyDecrypt fail. Error Code: %d", (int)returnCode);
    }
    else {
        result = [NSData dataWithBytes:plain
                                length:plainLen];
    }
    
    free(plain);
    free(cipher);
    
    return result;
}

#pragma mark - Random Data Generation
- (NSData *)randomDataOfLength:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    NSAssert(result == 0, @"Unable to generate random bytes: %d",
             errno);
    return data;
}

#pragma mark - AES Encryption
- (NSData *)aesEncryptData:(NSData *)data key:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSAssert(iv, @"IV must not be NULL");
    NSAssert(key, @"key must not be NULL");
    
    *iv = [self randomDataOfLength:kAlgorithmIVSize];
    *key = [self randomDataOfLength:kAlgorithmKeySize];
    
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kAlgorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     (*key).bytes, // key
                     (*key).length, // keylength
                     (*iv).bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            [NSError errorWithDomain:kObjectiveTLSErrorDomain
                                code:result
                            userInfo:nil];
        }
        return nil;
    }
    
    return cipherData;
}

#pragma mark - AES Decryption
- (NSData *)aesDecryptData:(NSData *)data
                       key:(NSData *)key
                       iv:(NSData *)iv
                    error:(NSError **)error {
    
    size_t outLength;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:data.length];
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt, // operation
                     kAlgorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     decryptedData.mutableBytes, // dataOut
                     decryptedData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        [decryptedData setLength:outLength];
    }
    else {
        if (result != kCCSuccess) {
            if (error) {
                *error = [NSError
                          errorWithDomain:kObjectiveTLSErrorDomain
                          code:result
                          userInfo:nil];
            }
            return nil;
        }
    }
    
    return decryptedData;
}

#pragma mark - Public TLS Methods
- (NSData *)aesEncryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *secret = nil;
    NSData *encryptedData = [self aesEncryptData:data key:&secret iv:iv error:error];
    *key = [self RSAEncryptData:secret];
    secret = nil;
    return encryptedData;
}

- (NSData *)aesEncryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *dataToEncrypt = [string dataUsingEncoding:kStringEncoding];
    return [self aesEncryptData:dataToEncrypt rsaEncryptedKey:key iv:iv error:error];
}

- (NSData *)aesDecryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *secret = [self RSADecryptData:key];
    if (secret) {
        NSData *decryptedData = [self aesDecryptData:data key:secret iv:iv error:error];
        secret = nil;
        return decryptedData;
    }
    return nil;
}

- (NSString *)aesStringDecryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *secret = [self RSADecryptData:key];
    if (secret) {
        NSData *decryptedData = [self aesDecryptData:data key:secret iv:iv error:error];
        secret = nil;
        return [[NSString alloc]initWithData:decryptedData encoding:kStringEncoding];
    }
    return nil;
}

#pragma mark - Memory Management
- (void)dealloc {
    CFRelease(privateKey),privateKey = nil;
    CFRelease(publicKey),publicKey = nil;
    CFRelease(certificate),certificate=nil;
    CFRelease(trust),trust=nil;
}

@end
