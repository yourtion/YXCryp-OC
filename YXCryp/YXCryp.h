//
//  YXCryp.h
//  YXCryp
//
//  Created by YourtionGuo on 8/12/16.
//  Copyright © 2016 Yourtion. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for YXCryp.
FOUNDATION_EXPORT double YXCrypVersionNumber;

//! Project version string for YXCryp.
FOUNDATION_EXPORT const unsigned char YXCrypVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <YXCryp/PublicHeader.h>

@interface YXCryp : NSObject

/**
 *  加密 NSData
 *
 *  @param key  秘钥
 *
 *  @return 加密结果
 */
+ (NSData *)encryptData:(NSData *)data WithKey:(NSString *)key;

/**
 *  解密 NSData
 *
 *  @param key 秘钥
 *
 *  @return 解密结果
 */
+ (NSData *)decryptData:(NSData *)data WithKey:(NSString *)key;

/**
 *  NSData 编码成 Base64 字符串
 *
 *  @return Base64 字符串
 */
+ (NSString *)base64StringFromData:(NSData *)data;

/**
 *  SHA256 哈希计算
 *
 *  @return SHA256结果
 */
+ (NSData *)sha256HashFromData:(NSData *)data;

/**
 *  SHA1 哈希计算
 *
 *  @return SHA1结果
*/
+ (NSData *)sha1HashFromData:(NSData *)data;

/**
 *  NSData 转换 HEX 字符串
 *
 *  @return HEX 字符串
 */
+ (NSString *)byteToStringFromData:(NSData *)data;

/**
 *  字符串 Base64 编码
 *
 *  @return  Base64 编码结果
 */
+ (NSString *)base64encodeFromString:(NSString *)string;

/**
 *  HEX 字符串转换 NSData
 *
 *  @return Data数据
 */
+ (NSData *)stringToByteFromString:(NSString *)string;

/**
 *  Base64 转换为 NSData
 *
 *  @return Data数据
 */
+ (NSData *)base64DataFromString:(NSString *)string;

@end


