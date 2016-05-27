//
//  CryptorTools.h
//  XianJinBao
//
//  Created by 廉英雷 on 16/3/4.
//  Copyright © 2016年 廉英雷. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface CryptorTools : NSObject

/**
 *  从字符串中加载公钥并加密
 *
 *  @param content   要加密的字符串
 *  @param publicStr 字符串公钥
 *
 *  @return <#return value description#>
 */
- (NSString *)loadPublicKeyFromString:(NSString *)content withPublicStr:(NSString *)publicStr;


///  加载公钥
///
///  @param filePath DER 公钥文件路径
- (void)loadPublicKeyWithFilePath:(NSString *)filePath;

///  加载私钥
///
///  @param filePath P12 私钥文件路径
///  @param password P12 密码
- (void)loadPrivateKey:(NSString *)filePath password:(NSString *)password;

///  RSA 加密数据
///
///  @param data 要加密的数据
///
///  @return 加密后的二进制数据
- (NSData *)RSAEncryptData:(NSData *)data;

///  RSA 加密字符串
///
///  @param string 要加密的字符串
///
///  @return 加密后的 BASE64 编码字符串
- (NSString *)RSAEncryptString:(NSString *)string;

///  RSA 解密数据
///
///  @param data 要解密的数据
///
///  @return 解密后的二进制数据
- (NSData *)RSADecryptData:(NSData *)data;

///  RSA 解密字符串
///
///  @param string 要解密的 BASE64 编码字符串
///
///  @return 解密后的字符串
- (NSString *)RSADecryptString:(NSString *)string;
@end
