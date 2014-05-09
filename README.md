ObjectiveTLS
=====================

Overview
---------

Transport Layer Security for securing data payloads in Objective-C. 

### What does it do?
**ObjectiveTLS** will secure data for transit similar to the handshake protocol of TLS. 
- Generate AES key
- Encrypt data payload with AES key
- Encrypt AES key with X.509 RSA public key
- Returns AES-encrypted payload and RSA-encrypted symmetric key 

### Installation
- Link project against `Security.framework`
- Add `ObjectiveTLS` folder to your project
- Import header (`#import "ObjectiveTLS.h"`)

How to use
---------

### Using Bundled X.509 Public Key
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
    NSData *salt = nil; // Randomly Generated Salt
    
    NSData *encryptedPayload = [otls aesEncryptString:@"Hello World Text"
                                      rsaEncryptedKey:&key
                                                   iv:&iv
                                                 salt:&salt
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
    NSData *salt = nil; // Randomly Generated Salt
    
    NSData *encryptedPayload = [otls aesEncryptData:dataToEncrypt
                                      rsaEncryptedKey:&key
                                                   iv:&iv
                                                 salt:&salt
                                                error:&err];
```

License
---------------

MIT
