//
//  DBTransitEncryption.m
//  DBTransitEncryption
//
//  Created by David Benko on 5/9/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//
// Thanks to:
// http://robnapier.net/aes-commoncrypto/   AES Encryption Algorithms
// https://github.com/xjunior/XRSA          RSA Encryption Algorithms
//

#import "DBTransitEncryption.h"

@interface DBTransitEncryption (){
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    SecCertificateRef certificate;
    SecPolicyRef policy;
    SecTrustRef trust;
    size_t maxPlainLen;
}
@end

@implementation DBTransitEncryption

static NSString * const kObjectiveTLSErrorDomain = @"com.davidbenko.dbtransitencryption";

#pragma mark - Init

- (DBTransitEncryption *)initWithX509PublicKeyData:(NSData *)base64KeyData {
    self = [super init];
    if (self) {
        
        // If public key read fails, return nil
        if(![self setPublicKey:base64KeyData]){
            return nil;
        }
        
        // Default values (RSA 128, AES 128, UTF8 encoding)
        _rsaKeySize = 1024;
        _rsaPadding = kSecPaddingPKCS1;
        
        _encryptorAlgorithm = kCCAlgorithmAES128;
        _encryptorAlgorithmOptions = kCCOptionPKCS7Padding;
        _encryptorAlgorithmKeySize = kCCKeySizeAES128;
        _encryptorAlgorithmBlockSize = kCCBlockSizeAES128;
        _encryptorAlgorithmIVSize = kCCBlockSizeAES128;
        _encryptorStringEncoding = NSUTF8StringEncoding;
        
    }
    
    return self;
}

- (DBTransitEncryption *)initWithX509PublicKey:(NSString *)publicKeyPath {
    if (publicKeyPath == nil) {
        NSLog(@"Can not find %@", publicKeyPath);
        return nil;
    }
    
    NSData *publicKeyFileContent = [NSData dataWithContentsOfFile:publicKeyPath];
    return [self initWithX509PublicKeyData:publicKeyFileContent];
}

#pragma mark - X.509 RSA Public Key (.der)
- (BOOL)setPublicKey:(NSData *)publicKeyContents{
    if (publicKeyContents == nil) {
        return false;
    }
    
    certificate = SecCertificateCreateWithData(kCFAllocatorDefault, ( __bridge CFDataRef) publicKeyContents);
    if (certificate == nil) {
        NSLog(@"Can not read certificate from data");
        return false;
    }
    
    policy = SecPolicyCreateBasicX509();
    OSStatus returnCode = SecTrustCreateWithCertificates(certificate, policy, &trust);
    if (returnCode != 0) {
        NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)returnCode);
        return false;
    }
    
    SecTrustResultType trustResultType;
    returnCode = SecTrustEvaluate(trust, &trustResultType);
    if (returnCode != 0) {
        return false;
    }
    
    publicKey = SecTrustCopyPublicKey(trust);
    if (publicKey == nil) {
        NSLog(@"SecTrustCopyPublicKey fail");
        return false;
    }
    
    maxPlainLen = SecKeyGetBlockSize(publicKey) - 12;
    
    return true;
}

#pragma mark - PKCS#12 RSA Private Key (.p12)
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
        return false;
    }
    
    NSDictionary* item = (NSDictionary*) CFArrayGetValueAtIndex(importedItems, 0);
    SecIdentityRef  identity = (__bridge SecIdentityRef) [item objectForKey:(__bridge NSString *) kSecImportItemIdentity];
    SecIdentityCopyPrivateKey(identity, &privateKey);
    if (privateKey == nil) {
        NSLog(@"SecIdentityCopyPrivateKey fail");
        return false;
    }
    
    return true;
}

#pragma mark - Random Data Generation
NSData* randomDataOfLength(size_t length){
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    
    assert(result == 0);
    return data;
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
    
    size_t cipherLen = (self.rsaKeySize / 8); // convert to byte
    void *cipher = malloc(cipherLen);
    
    OSStatus returnCode = SecKeyEncrypt(publicKey, self.rsaPadding, plain,
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
    
    OSStatus returnCode = SecKeyDecrypt(privateKey, self.rsaPadding, cipher,
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

#pragma mark - Symmetric Encryption
- (NSData *)encryptData:(NSData *)data key:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSAssert(key, @"key must not be NULL");
    
    if (iv != NULL) {
        *iv = randomDataOfLength(self.encryptorAlgorithmIVSize);
    }
    *key = randomDataOfLength(self.encryptorAlgorithmKeySize);
    
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + self.encryptorAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt,                            // operation
                     self.encryptorAlgorithm,               // Algorithm
                     self.encryptorAlgorithmOptions,        // options
                     (*key).bytes,                          // key
                     (*key).length,                         // keylength
                     (iv != NULL) ? (*iv).bytes : NULL,     // iv
                     data.bytes,                            // dataIn
                     data.length,                           // dataInLength,
                     cipherData.mutableBytes,               // dataOut
                     cipherData.length,                     // dataOutAvailable
                     &outLength);                           // dataOutMoved
    
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
    
    if (self.ivMixer) {
        self.ivMixer(&cipherData,key,*iv);
    }
    
    return cipherData;
}

#pragma mark - Symmetric Decryption
- (NSData *)decryptData:(NSData *)data key:(NSData *)key iv:(NSData *)iv error:(NSError **)error {
    NSAssert(key, @"key must not be NULL");
    
    if(self.ivSeparator){
        iv = self.ivSeparator(&data,&key);
    }
    
    size_t outLength;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:data.length];
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt,                        // operation
                     self.encryptorAlgorithm,           // Algorithm
                     self.encryptorAlgorithmOptions,    // options
                     key.bytes,                         // key
                     key.length,                        // keylength
                     (iv != NULL) ? iv.bytes : NULL,    // iv
                     data.bytes,                        // dataIn
                     data.length,                       // dataInLength,
                     decryptedData.mutableBytes,        // dataOut
                     decryptedData.length,              // dataOutAvailable
                     &outLength);                       // dataOutMoved
    
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

#pragma mark - Public Encryption Methods
- (NSData *)encryptData:(NSData *)data rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *secret = nil;
    NSData *encryptedData = [self encryptData:data key:&secret iv:iv error:error];
    *key = [self RSAEncryptData:secret];
    secret = nil;
    return encryptedData;
}

- (NSData *)encryptData:(NSData *)data withIVMixer:(IVMixerBlock)ivMixer rsaEncryptedKey:(NSData **)key error:(NSError **)error{
    NSData *iv = nil;
    IVMixerBlock temp = self.ivMixer;
    self.ivMixer = ivMixer;
    NSData *encryptedData = [self encryptData:data rsaEncryptedKey:key iv:&iv error:error];
    self.ivMixer = temp;
    return encryptedData;
}

- (NSData *)encryptString:(NSString *)string rsaEncryptedKey:(NSData **)key iv:(NSData **)iv error:(NSError **)error{
    NSData *dataToEncrypt = [string dataUsingEncoding:self.encryptorStringEncoding];
    return [self encryptData:dataToEncrypt rsaEncryptedKey:key iv:iv error:error];
}

- (NSData *)encryptString:(NSString *)string withIVMixer:(IVMixerBlock)ivMixer rsaEncryptedKey:(NSData **)key error:(NSError **)error {
    NSData *dataToEncrypt = [string dataUsingEncoding:self.encryptorStringEncoding];
    return [self encryptData:dataToEncrypt withIVMixer:ivMixer rsaEncryptedKey:key error:error];
}

#pragma mark - Public Decryption Methods
- (NSData *)decryptData:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
    NSData *secret = [self RSADecryptData:key];
    if (secret) {
        NSData *decryptedData = [self decryptData:data key:secret iv:iv error:error];
        secret = nil;
        return decryptedData;
    }
    return nil;
}

- (NSData *)decryptData:(NSData *)data withIVSeparator:(IVSeparatorBlock)ivSeparator rsaEncryptedKey:(NSData *)key error:(NSError **)error{
    NSData *iv = nil;
    IVSeparatorBlock temp = self.ivSeparator;
    self.ivSeparator = ivSeparator;
    NSData *decryptedData = [self decryptData:data rsaEncryptedKey:key iv:iv error:error];
    self.ivSeparator = temp;
    return decryptedData;
}

- (NSString *)decryptString:(NSData *)data rsaEncryptedKey:(NSData *)key iv:(NSData *)iv error:(NSError **)error{
	NSData *decryptedData = [self decryptData:data rsaEncryptedKey:key iv:iv error:error];
	return [[NSString alloc]initWithData:decryptedData encoding:self.encryptorStringEncoding];
}

- (NSString *)decryptString:(NSData *)data withIVSeparator:(IVSeparatorBlock)ivSeparator rsaEncryptedKey:(NSData *)key error:(NSError **)error{
    NSData *decryptedData = [self decryptData:data withIVSeparator:ivSeparator rsaEncryptedKey:key error:error];
    return [[NSString alloc]initWithData:decryptedData encoding:self.encryptorStringEncoding];
}

#pragma mark - Memory Management
- (void)dealloc {
    CFRelease(privateKey),privateKey = nil;
    CFRelease(publicKey),publicKey = nil;
    CFRelease(certificate),certificate=nil;
    CFRelease(trust),trust=nil;
}

@end