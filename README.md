ObjectiveTLS
=====================

Overview
---------

Transport Layer Security for securing data payloads in Objective-C. An easy way to secure data by providing a symmetric key for that transaction. Keys are generated on the fly and every message will have a new key. 

**TL;DR** AES encrypts data with a random key, RSA encrypts key and provides both.

### What does it do?
**ObjectiveTLS** will secure data for transit similar to the handshake protocol of TLS. 
- Generate AES symmetric key
- Encrypt data payload with AES key
- Encrypt AES key with X.509 RSA public key
- Returns AES-encrypted payload and RSA-encrypted symmetric key 

### Installation
- Link project against `Security.framework`
- Add `ObjectiveTLS` folder to your project
- Import header (`#import "ObjectiveTLS.h"`)

Encryption
---------

### Using Bundled X.509 Public Key (.der)
```objc
   
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:@"public_key"
                                                        ofType:@"der"];
    
    ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKey:keyPath];
```

### Using in-memory X.509 Public Key (Recommended)
```objc
    
	NSString *publicKey = @"MIICs ... kT0=\n"; // Base64 encoded key
    NSData *data = [[NSData alloc] initWithBase64EncodedString:publicKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKeyData:data];
```

### Encrypt NSString
```objc
    
	ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKey:keyPath];
    NSError *err = nil;
    NSData *key = nil;  // AES Key, Encrypted with RSA public key
    NSData *iv = nil;   // Randomly Generated IV
    
    NSData *encryptedPayload = [otls aesEncryptString:@"Hello World Text"
                                      rsaEncryptedKey:&key
                                                   iv:&iv
                                                error:&err];
```

### Encrypt NSData
```objc
    
	NSString *string = @"Hello World Text";
    NSData *dataToEncrypt = [string dataUsingEncoding:kStringEncoding];
	
    ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKey:keyPath];
    NSError *err = nil;
    NSData *key = nil;  // AES Key, Encrypted with RSA public key
    NSData *iv = nil;   // Randomly Generated IV
    
    NSData *encryptedPayload = [otls aesEncryptData:dataToEncrypt
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
	
    ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKey:publicKeyPath];
	[otls setPrivateKey:privateKeyPath withPassphrase:privateKeyPassword];
```

### Decrypt NSData
```objc

    NSData *aesEncryptedData; //some encrypted data
	NSData *rsaEncryptedKey; // some encrypted key
	NSData *iv = nil; // some iv
	
    ObjectiveTLS *otls = [[ObjectiveTLS alloc]initWithX509PublicKey:publicKeyPath];
	[otls setPrivateKey:privateKeyPath withPassphrase:@".p12 password"];
    NSError *err = nil;
	    
    NSData *decryptedPayload = [otls aesDecryptData:dataToEncrypt
                                      rsaEncryptedKey:key
                                                   iv:iv
                                                error:&err];
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
