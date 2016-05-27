//
//  CryptorTools.m
//  XianJinBao
//
//  Created by 廉英雷 on 16/3/4.
//  Copyright © 2016年 廉英雷. All rights reserved.
//

#import "CryptorTools.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import "Base64.h"
#import "SecKey.h"

// 填充模式
#define kTypeOfWrapPadding		kSecPaddingPKCS1

@interface CryptorTools() {
      SecKeyRef _publicKeyRef;                             // 公钥引用
      SecKeyRef _privateKeyRef;                            // 私钥引用
}

@end

@implementation CryptorTools


#pragma mark - RSA 加密/解密算法

//- (void)loadPublicKeyWithString:(NSString *)publickKeyStr{
//
//      publickKeyStr = [@"-----BEGIN PUBLIC KEY-----" stringByAppendingString:publickKeyStr];
//      publickKeyStr = [publickKeyStr stringByAppendingString:@"-----END PUBLIC KEY-----"];
//      // 删除当前公钥
//      if (_publicKeyRef) CFRelease(_publicKeyRef);
//      
//      // 从一个 DER 表示的证书创建一个证书对象
//      NSData *certificateData = [publickKeyStr base64DecodedData];
//      SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
//    //  NSAssert(certificateRef != NULL, @"公钥文件错误");
//      
//      // 返回一个默认 X509 策略的公钥对象，使用之后需要调用 CFRelease 释放
//      SecPolicyRef policyRef = SecPolicyCreateBasicX509();
//      // 包含信任管理信息的结构体
//      SecTrustRef trustRef;
//      
//      // 基于证书和策略创建一个信任管理对象
//      OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
//      NSAssert(status == errSecSuccess, @"创建信任管理对象失败");
//      
//      // 信任结果
//      SecTrustResultType trustResult;
//      // 评估指定证书和策略的信任管理是否有效
//      status = SecTrustEvaluate(trustRef, &trustResult);
//      NSAssert(status == errSecSuccess, @"信任评估失败");
//      
//      // 评估之后返回公钥子证书
//      _publicKeyRef = SecTrustCopyPublicKey(trustRef);
//      NSAssert(_publicKeyRef != NULL, @"公钥创建失败");
//      
//      if (certificateRef) CFRelease(certificateRef);
//      if (policyRef) CFRelease(policyRef);
//      if (trustRef) CFRelease(trustRef);
//
//}
- (void)loadPublicKeyWithFilePath:(NSString *)filePath; {
      
      NSAssert(filePath.length != 0, @"公钥路径为空");
      
      // 删除当前公钥
      if (_publicKeyRef) CFRelease(_publicKeyRef);
      
      // 从一个 DER 表示的证书创建一个证书对象
      NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
      
      SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
      NSAssert(certificateRef != NULL, @"公钥文件错误");
      
      // 返回一个默认 X509 策略的公钥对象，使用之后需要调用 CFRelease 释放
      SecPolicyRef policyRef = SecPolicyCreateBasicX509();
      // 包含信任管理信息的结构体
      SecTrustRef trustRef;
      
      // 基于证书和策略创建一个信任管理对象
      OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
      NSAssert(status == errSecSuccess, @"创建信任管理对象失败");
      
      // 信任结果
      SecTrustResultType trustResult;
      // 评估指定证书和策略的信任管理是否有效
      status = SecTrustEvaluate(trustRef, &trustResult);
      NSAssert(status == errSecSuccess, @"信任评估失败");
      
      // 评估之后返回公钥子证书
      _publicKeyRef = SecTrustCopyPublicKey(trustRef);
      NSAssert(_publicKeyRef != NULL, @"公钥创建失败");
      
      if (certificateRef) CFRelease(certificateRef);
      if (policyRef) CFRelease(policyRef);
      if (trustRef) CFRelease(trustRef);
}

- (void)loadPrivateKey:(NSString *)filePath password:(NSString *)password {
      
      NSAssert(filePath.length != 0, @"私钥路径为空");
      
      // 删除当前私钥
      if (_privateKeyRef) CFRelease(_privateKeyRef);
      
      NSData *PKCS12Data = [NSData dataWithContentsOfFile:filePath];
      CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
      CFStringRef passwordRef = (__bridge CFStringRef)password;
      
      // 从 PKCS #12 证书中提取标示和证书
      SecIdentityRef myIdentity;
      SecTrustRef myTrust;
      const void *keys[] = {kSecImportExportPassphrase};
      const void *values[] = {passwordRef};
      CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
      CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
      
      // 返回 PKCS #12 格式数据中的标示和证书
      OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
      
      if (status == noErr) {
            CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
            myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
            myTrust = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
      }
      
      if (optionsDictionary) CFRelease(optionsDictionary);
      
      NSAssert(status == noErr, @"提取身份和信任失败");
      
      SecTrustResultType trustResult;
      // 评估指定证书和策略的信任管理是否有效
      status = SecTrustEvaluate(myTrust, &trustResult);
      NSAssert(status == errSecSuccess, @"信任评估失败");
      
      // 提取私钥
      status = SecIdentityCopyPrivateKey(myIdentity, &_privateKeyRef);
      NSAssert(status == errSecSuccess, @"私钥创建失败");
      CFRelease(items);
}

- (NSString *)RSAEncryptString:(NSString *)string {
      NSData *cipher = [self RSAEncryptData:[string dataUsingEncoding:NSUTF8StringEncoding]];
      
      return [cipher base64EncodedStringWithOptions:0];
}

- (NSData *)RSAEncryptData:(NSData *)data {
      OSStatus sanityCheck = noErr;
      size_t cipherBufferSize = 0;
      size_t keyBufferSize = 0;
      
      NSAssert(data, @"明文数据为空");
      NSAssert(_publicKeyRef, @"公钥为空");
      
      NSData *cipher = nil;
      uint8_t *cipherBuffer = NULL;
      
      // 计算缓冲区大小
      cipherBufferSize = SecKeyGetBlockSize(_publicKeyRef);
      keyBufferSize = data.length;
      
      if (kTypeOfWrapPadding == kSecPaddingNone) {
            NSAssert(keyBufferSize <= cipherBufferSize, @"加密内容太大");
      } else {
            NSAssert(keyBufferSize <= (cipherBufferSize - 11), @"加密内容太大");
      }
      
      // 分配缓冲区
      cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
      memset((void *)cipherBuffer, 0x0, cipherBufferSize);
      
      // 使用公钥加密
      sanityCheck = SecKeyEncrypt(_publicKeyRef,
                                  kTypeOfWrapPadding,
                                  (const uint8_t *)data.bytes,
                                  keyBufferSize,
                                  cipherBuffer,
                                  &cipherBufferSize
                                  );
      
      NSAssert(sanityCheck == noErr, @"加密错误，OSStatus == %d", sanityCheck);
      
      // 生成密文数据
      cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
      
      if (cipherBuffer) free(cipherBuffer);
      
      return cipher;
}

- (NSString *)RSADecryptString:(NSString *)string {
      NSData *keyData = [self RSADecryptData:[[NSData alloc] initWithBase64EncodedString:string options:0]];
      
      return [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
}

- (NSData *)RSADecryptData:(NSData *)data {
      OSStatus sanityCheck = noErr;
      size_t cipherBufferSize = 0;
      size_t keyBufferSize = 0;
      
      NSData *key = nil;
      uint8_t *keyBuffer = NULL;
      
      SecKeyRef privateKey = _privateKeyRef;
      NSAssert(privateKey != NULL, @"私钥不存在");
      
      // 计算缓冲区大小
      cipherBufferSize = SecKeyGetBlockSize(privateKey);
      keyBufferSize = data.length;
      
      NSAssert(keyBufferSize <= cipherBufferSize, @"解密内容太大");
      
      // 分配缓冲区
      keyBuffer = malloc(keyBufferSize * sizeof(uint8_t));
      memset((void *)keyBuffer, 0x0, keyBufferSize);
      
      // 使用私钥解密
      sanityCheck = SecKeyDecrypt(privateKey,
                                  kTypeOfWrapPadding,
                                  (const uint8_t *)data.bytes,
                                  cipherBufferSize,
                                  keyBuffer,
                                  &keyBufferSize
                                  );
      
      NSAssert1(sanityCheck == noErr, @"解密错误，OSStatus == %d", sanityCheck);
      
      // 生成明文数据
      key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];
      
      if (keyBuffer) free(keyBuffer);
      
      return key;
}




- (NSString *)loadPublicKeyFromString:(NSString *)content withPublicStr:(NSString *)publicStr

{
      
//      NSData *publicKey = [NSData dataWithBase64EncodedString:@"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKuFpNr12KiOUm60p4SRj97baOffagQbuKbDB4hvoDPTCmtw4gU4Ti71D7kR8Qo9XgMk5fJLQ/dBOyCOC0bJ188CAwEAAQ=="];
////      ;
      NSData *publicKey = [NSData dataWithBase64EncodedString:publicStr];
    
      
      NSData *usernamm = [content dataUsingEncoding: NSUTF8StringEncoding];
      
      NSData *newKey= [SecKey encrypt:usernamm publicKey:publicKey];
      
      NSString *result = [newKey base64EncodedString];
      
      return result;
      
}

@end
