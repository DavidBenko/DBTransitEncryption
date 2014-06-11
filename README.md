DBTransitEncryption
=====================

Overview
---------

Transport Layer Security for securing data payloads in Objective-C. An easy way to secure data by providing a symmetric key for that transaction. Keys are generated on the fly and every message will have a new key. 

**TL;DR** AES encrypts data with a random key, RSA encrypts key and provides both.

### What does it do?
**DBTransitEncryption** will secure data for transit similar to the handshake protocol of TLS. 
- Generate AES symmetric key
- Encrypt data payload with AES key
- Encrypt AES key with X.509 RSA public key
- Returns AES-encrypted payload and RSA-encrypted symmetric key 

### Installation

##### Via CocoaPods
- Add `pod 'DBTransitEncryption'` to your podfile
- Run `pod install`
 
##### Manual Installation
- Link project against `Security.framework`
- Add `DBTransitEncryption` folder to your project
- Import header (`#import "DBTransitEncryption.h"`)

### Generate X.509 RSA Key Pair
- Run the following commands to generate a personal key pair for testing. 
- The files you care about are `public_key.der` and `private_key.p12`

```shell
openssl req -x509 -out public_key.der -outform der -new -newkey rsa:1024 -keyout private_key.pem -days 3650
openssl x509 -inform der -outform pem -in public_key.der -out public_key.pem
openssl pkcs12 -export -in public_key.pem -inkey private_key.pem -out private_key.p12
```



Encryption
---------

### Using Bundled X.509 Public Key (.der)
```objc
   
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:@"public_key"
                                                        ofType:@"der"];
    
    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKey:keyPath];
```

### Using in-memory X.509 Public Key (Recommended)
```objc
    
	NSString *publicKey = @"MIICs ... kT0=\n"; // Base64 encoded key
    NSData *data = [[NSData alloc] initWithBase64EncodedString:publicKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKeyData:data];
```

### Encrypt NSString
```objc
    
	DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKey:keyPath];
    NSError *err = nil;
    NSData *key = nil;  // AES Key, Encrypted with RSA public key
    NSData *iv = nil;   // Randomly Generated IV
    
    NSData *encryptedPayload = [encryptor encryptString:@"Hello World Text"
                                      rsaEncryptedKey:&key
                                                   iv:&iv
                                                error:&err];
```

### Encrypt NSData
```objc
    
	NSString *string = @"Hello World Text";
    NSData *dataToEncrypt = [string dataUsingEncoding:kStringEncoding];
	
    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKey:keyPath];
    NSError *err = nil;
    NSData *key = nil;  // AES Key, Encrypted with RSA public key
    NSData *iv = nil;   // Randomly Generated IV
    
    NSData *encryptedPayload = [encryptor encryptData:dataToEncrypt
                                      rsaEncryptedKey:&key
                                                   iv:&iv
                                                error:&err];
```

Decryption
---------

### Using Bundled PKCS#12 RSA Private Key (.p12)
```objc
	
	NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"];
	NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"];
    NSString *privateKeyPassword = @"Password for .p12 file"
	
    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKey:publicKeyPath];
	[encryptor setPrivateKey:privateKeyPath withPassphrase:privateKeyPassword];
```

### Decrypt NSData
```objc

    NSData *aesEncryptedData; //some encrypted data
	NSData *rsaEncryptedKey; // some encrypted key
	NSData *iv = nil; // some iv
	
    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKey:publicKeyPath];
	[encryptor setPrivateKey:privateKeyPath withPassphrase:@".p12 password"];
    NSError *err = nil;
	    
    NSData *decryptedPayload = [encryptor decryptData:dataToEncrypt
                                      rsaEncryptedKey:key
                                                   iv:iv
                                                error:&err];
```

Public Properties
---------
**DBTransitEncryption** has a few public properties which allow you to modify the encryption algorithms to suit your project's needs.

```objc
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
```


IV Mixer Blocks
---------
**DBTransitEncryption** allows you to define custom blocks to mix and separate the initialization vector with the key and/or the encrypted data. 

The `ivMixer` gives access to the data, key, and iv immediately after the data is encrypted, but before the key is encrypted. This allows you to mix the iv with key before it is RSA encrypted, to further secure the iv.

The `ivSeparator` is the opposite of the `ivMixer`. The `ivSeparator` should be implemented in a way which undoes the mixing algorithm and returns the iv. **The `ivSeparator` is only needed for decryption.**

### IV Mixing Example
```objc

    DBTransitEncryption *encryptor = [[DBTransitEncryption alloc]initWithX509PublicKeyData:pubkeyb64data];
    
    // Prepends the iv to the key before the key is encrypted
    
    [encryptor setIvMixer:^(NSData **data,NSData **key, NSData *iv){
        NSMutableData *mutableKey = [iv mutableCopy];
        [mutableKey appendBytes:[*key bytes] length:[*key length]];
        *key = mutableKey;
    }];
    
    // Extracts the iv from the key before decryption
    
    [encryptor setIvSeparator:^NSData *(NSData **data, NSData **key){
        NSInteger ivSize = 16;
        NSMutableData *mutableKey = [*key mutableCopy];
        NSRange range = NSMakeRange(0, ivSize);
        NSData *iv = [mutableKey subdataWithRange:range];
        [mutableKey replaceBytesInRange:range withBytes:NULL length:0];
        *key = mutableKey;
        return iv;
    }];
```


License
---------------

The MIT License (MIT)

Copyright (c) 2014 David Benko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
