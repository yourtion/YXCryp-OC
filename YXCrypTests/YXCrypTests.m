//
//  YXCrypTests.m
//  YXCrypTests
//
//  Created by YourtionGuo on 8/12/16.
//  Copyright © 2016 Yourtion. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "YXCryp.h"

@interface YXCrypTests : XCTestCase

@end

@implementation YXCrypTests

static NSString *TEST_KEY = @"123456";
static NSString *TEST_STRING = @"Yourtion";
static NSString *TEST_STRING_BASE64 = @"WW91cnRpb24=";
static NSString *TEST_STRING_HEX = @"596f757274696f6e";
static NSString *TEST_STRING_SHA1 = @"13ab3dc8bac77382174cd40c09634a06afd5d8f9";
static NSString *TEST_STRING_SHA256 = @"dc7f60dfbdc17b16936e50da5641e868264972b0cd327a4efb1ab1f9eeeac29e";


- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

/**
 *  加密解密 NSData
 */
- (void)testAES256EncryptDecryptDataWithKey {
    NSData *stringData = [TEST_STRING dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encrypted = [YXCryp encryptData:stringData AES256WithKey:TEST_KEY];
    NSData *decrypted = [YXCryp decryptData:encrypted AES256WithKey:TEST_KEY];
    
    NSString *result = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, TEST_STRING);
}

/**
 *  SHA256 哈希计算
 */
- (void)testSha256HashFromData {
    NSData *stringData = [TEST_STRING dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *sha256 = [YXCryp sha256HashFromData:stringData];
    
    NSString *result = [YXCryp byteToStringFromData:sha256];
    XCTAssertEqualObjects(result, TEST_STRING_SHA256);
}

/**
 *  SHA1 哈希计算
 */
- (void)testSha1HashFromData {
    NSData *stringData = [TEST_STRING dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *sha1 = [YXCryp sha1HashFromData:stringData];
    
    NSString *result = [YXCryp byteToStringFromData:sha1];
    XCTAssertEqualObjects(result, TEST_STRING_SHA1);
}

/**
 *  NSData 转换 HEX 字符串
 */
- (void)testByteToStringFromData {
    NSData *stringData = [TEST_STRING dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *result = [YXCryp byteToStringFromData:stringData];

    XCTAssertEqualObjects(result, TEST_STRING_HEX);
}

/**
 *  HEX 字符串转换 NSData
 */
- (void)testStringToByteFromString {
    NSData *hex = [YXCryp stringToByteFromString:TEST_STRING_HEX];
    
    NSString *result = [[NSString alloc] initWithData:hex encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, TEST_STRING);
}

/**
 *  NSData 编码成 Base64 字符串
 */
- (void)testBase64StringFromData {
    NSData *stringData = [TEST_STRING dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *result = [YXCryp base64StringFromData:stringData];
    
    XCTAssertEqualObjects(result, TEST_STRING_BASE64);
}

/**
 *  NSString 编码成 Base64 字符串
 */
- (void)testBase64encodeFromString {    
    NSString *result = [YXCryp base64encodeFromString:TEST_STRING];
    
    XCTAssertEqualObjects(result, TEST_STRING_BASE64);
}

/**
 *  Base64 字符串转换为 NSData
 */
- (void)testBase64DataFromString {
    NSData *base64 = [YXCryp base64DataFromString:TEST_STRING_BASE64];
    
    NSString *result = [[NSString alloc] initWithData:base64 encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, TEST_STRING);

}

@end
