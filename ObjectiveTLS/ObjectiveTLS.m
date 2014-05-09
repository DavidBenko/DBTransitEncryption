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
static const NSUInteger kPBKDFSaltSize = 8;
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

#pragma mark - RSA Encryption
- (NSData *) RSAEncryptData:(NSData *)content {
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
- (NSData *)aesEncryptData:(NSData *)data key:(NSData **)key iv:(NSData **)iv salt:(NSData **)salt error:(NSError **)error{
    NSAssert(iv, @"IV must not be NULL");
    NSAssert(salt, @"salt must not be NULL");
    NSAssert(key, @"key must not be NULL");
    
    *iv = [self randomDataOfLength:kAlgorithmIVSize];
    *salt = [self randomDataOfLength:kPBKDFSaltSize];
    *key = [self randomDataOfLength:kAlgorithmKeySize];
    
    size_t outLength;
    NSMutableData *
    cipherData = [NSMutableData dataWithLength:data.length +
                  kAlgorithmBlockSize];
    
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


#pragma mark - Public TLS Methods
- (NSData *)aesEncryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv salt:(NSData **)salt error:(NSError **)error{
    NSData *secret = nil;
    NSData *encryptedData = [self aesEncryptData:data key:&secret iv:iv salt:salt error:error];
    *key = [self RSAEncryptData:secret];
    secret = nil;
    return encryptedData;
}

- (NSData *)aesEncryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv salt:(NSData **)salt error:(NSError **)error{
    NSData *dataToEncrypt = [string dataUsingEncoding:kStringEncoding];
    return [self aesEncryptData:dataToEncrypt rsaEncryptedKey:key iv:iv salt:salt error:error];
}

@end
