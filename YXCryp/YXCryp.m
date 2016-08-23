//
//  YXCrypString.m
//  YXCryp
//
//  Created by YourtionGuo on 8/23/16.
//  Copyright © 2016 Yourtion. All rights reserved.
//

#import "YXCryp.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation YXCryp

static char YXCbase64EncodingTable[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

static char YXCbase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

+ (NSData *)encryptData:(NSData *)data WithKey:(NSString *)key {
    NSData *keyData = [YXCryp sha256HashFromData:[key dataUsingEncoding:NSUTF8StringEncoding]];
    return [YXCryp _encryptData:data WithKeyData:keyData];
}

+ (NSData *)decryptData:(NSData *)data WithKey:(NSString *)key {
    NSData *keyData = [YXCryp sha256HashFromData:[key dataUsingEncoding:NSUTF8StringEncoding]];
    return [YXCryp _decryptData:data WithKeyData:keyData];
}

+ (NSData *)_runCryptor:(CCCryptorRef)cryptor withData:(NSData *)data result:(CCCryptorStatus *)status {
    size_t bufsize = CCCryptorGetOutputLength( cryptor, (size_t)[data length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    *status = CCCryptorUpdate( cryptor, [data bytes], (size_t)[data length],buf, bufsize, &bufused );
    if (*status != kCCSuccess) {
        free( buf );
        return ( nil );
    }
    bytesTotal += bufused;
    
    *status = CCCryptorFinal( cryptor, buf + bufused, bufsize - bufused, &bufused );
    if (*status != kCCSuccess) {
        free(buf);
        return nil;
    }
    bytesTotal += bufused;
    
    return ([NSData dataWithBytesNoCopy:buf length:bytesTotal]);
}

+ (NSData *)_encryptData:(NSData *)data WithKeyData:(NSData *)key {
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus *error;
    NSParameterAssert([key isKindOfClass: [NSData class]]);
    
    status = CCCryptorCreate(kCCEncrypt,
                             kCCAlgorithmAES128,
                             kCCOptionECBMode|kCCOptionPKCS7Padding,
                             [key bytes],
                             [key length],
                             NULL,
                             &cryptor
                             );
    
    if (status != kCCSuccess) {
        if (error != NULL) {
            *error = status;
        }
        return  nil;
    }
    
    NSData *result = [self _runCryptor: cryptor withData:data result: &status];
    if ((result == nil) && (error != NULL)) {
        *error = status;
    }
    CCCryptorRelease(cryptor);
    
    if (result != nil){
        return result ;
    }
    return nil;
}

+ (NSData *)_decryptData:(NSData *)data WithKeyData:(NSData *)key{
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus * error;
    NSParameterAssert([key isKindOfClass: [NSData class]]);
    
    status = CCCryptorCreate(kCCDecrypt,
                             kCCAlgorithmAES128,
                             kCCOptionECBMode |kCCOptionPKCS7Padding,
                             [key bytes],
                             [key length],
                             NULL,
                             &cryptor
                             );
    
    if (status != kCCSuccess) {
        if (error != NULL) {
            *error = status;
        }
        return nil;
    }
    
    NSData *result = [self _runCryptor: cryptor withData:data result: &status];
    if ((result == nil) && (error != NULL)){
        *error = status;
    }
    CCCryptorRelease(cryptor);
    
    return result;
}

+ (NSString *)byteToStringFromData:(NSData *)data  {
    Byte *plainTextByte = (Byte *)[data bytes];
    NSString *hexStr=@"";
    for(int i=0;i<[data length];i++) {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",plainTextByte[i]&0xff];///16进制数
        if([newHexStr length]==1) {
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        } else {
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
        }
    }
    return hexStr;
}

+ (NSString *)base64StringFromData:(NSData *)data {
    unsigned long ixtext, lentext;
    long ctremaining;
    unsigned char input[3], output[4];
    short i, charsonline = 0, ctcopy;
    const unsigned char *raw;
    NSMutableString *result;
    
    lentext = [data length];
    if (lentext < 1) {
        return @"";
    }
    result = [NSMutableString stringWithCapacity: lentext];
    raw = [data bytes];
    ixtext = 0;
    
    while (true) {
        ctremaining = lentext - ixtext;
        if (ctremaining <= 0) {
            break;
        }
        for (i = 0; i < 3; i++) {
            unsigned long ix = ixtext + i;
            if (ix < lentext) {
                input[i] = raw[ix];
            }
            else {
                input[i] = 0;
            }
        }
        output[0] = (input[0] & 0xFC) >> 2;
        output[1] = ((input[0] & 0x03) << 4) | ((input[1] & 0xF0) >> 4);
        output[2] = ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6);
        output[3] = input[2] & 0x3F;
        ctcopy = 4;
        switch (ctremaining) {
            case 1:
                ctcopy = 2;
                break;
            case 2:
                ctcopy = 3;
                break;
        }
        
        for (i = 0; i < ctcopy; i++) {
            [result appendString: [NSString stringWithFormat: @"%c", YXCbase64EncodingTable[output[i]]]];
        }
        
        for (i = ctcopy; i < 4; i++) {
            [result appendString: @"="];
        }
        
        ixtext += 3;
        charsonline += 4;
        
        NSUInteger length = [data length];
        
        if ((length > 0) && (charsonline >= length)) {
            charsonline = 0;
        }
    }
    return result;
}

+ (NSData *)sha256HashFromData:(NSData *)data {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    (void) CC_SHA256( [data bytes], (CC_LONG)[data length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA256_DIGEST_LENGTH] );
}

+ (NSData *)sha1HashFromData:(NSData *)data {
    //使用对应的CC_SHA1,CC_SHA256,CC_SHA384,CC_SHA512的长度分别是20,32,48,64
    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    //使用对应的CC_SHA256,CC_SHA384,CC_SHA512
    (void) CC_SHA1([data bytes], (CC_LONG)[data length], hash);
    return ( [NSData dataWithBytes: hash length: CC_SHA1_DIGEST_LENGTH] );
}


+ (NSData *)stringToByteFromString:(NSString *)string {
    NSString *hexString=[[string uppercaseString] stringByReplacingOccurrencesOfString:@" " withString:@""];
    if ([hexString length]%2!=0) {
        return nil;
    }
    Byte tempbyt[1]={0};
    NSMutableData* bytes=[NSMutableData data];
    for(int i=0;i<[hexString length];i++) {
        unichar hex_char1 = [hexString characterAtIndex:i]; ////两位16进制数中的第一位(高位*16)
        int int_ch1;
        if(hex_char1 >= '0' && hex_char1 <='9') {
            int_ch1 = (hex_char1-48)*16;   //// 0 的Ascll - 48
        } else if(hex_char1 >= 'A' && hex_char1 <='F') {
            int_ch1 = (hex_char1-55)*16; //// A 的Ascll - 65
        } else {
            return nil;
        }
        
        i++;
        
        unichar hex_char2 = [hexString characterAtIndex:i]; ///两位16进制数中的第二位(低位)
        int int_ch2;
        if(hex_char2 >= '0' && hex_char2 <='9') {
            int_ch2 = (hex_char2-48); //// 0 的Ascll - 48
        } else if(hex_char2 >= 'A' && hex_char2 <='F') {
            int_ch2 = hex_char2-55; //// A 的Ascll - 65
        } else {
            return nil;
        }
        
        tempbyt[0] = int_ch1+int_ch2;  ///将转化后的数放入Byte数组里
        [bytes appendBytes:tempbyt length:1];
    }
    return bytes;
}

+ (NSString *)base64encodeFromString:(NSString *)string {
    if ([string length] == 0) {
        return @"";
    }
    
    const char *source = [string UTF8String];
    int strlength  = (int)strlen(source);
    char *characters = malloc(((strlength + 2) / 3) * 4);
    
    if (characters == NULL){
        return nil;
    }
    
    NSUInteger length = 0;
    NSUInteger i = 0;
    
    while (i < strlength) {
        
        char buffer[3] = {0,0,0};
        short bufferLength = 0;
        while (bufferLength < 3 && i < strlength) {
            buffer[bufferLength++] = source[i++];
        }
        
        characters[length++] = YXCbase64[(buffer[0] & 0xFC) >> 2];
        characters[length++] = YXCbase64[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        
        if (bufferLength > 1) {
            characters[length++] = YXCbase64[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
        } else {
            characters[length++] = '=';
        }
        
        if (bufferLength > 2) {
            characters[length++] = YXCbase64[buffer[2] & 0x3F];
        } else {
            characters[length++] = '=';
        }
    }
    
    return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES];
}

+ (NSData *)base64DataFromString:(NSString *)string {
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[3];
    short i, ixinbuf;
    Boolean flignore, flendtext = false;
    const unsigned char *tempcstring;
    NSMutableData *theData;
    
    if (self == nil) {
        return [NSData data];
    }
    
    ixtext = 0;
    tempcstring = (const unsigned char *)[string UTF8String];
    lentext = [string length];
    theData = [NSMutableData dataWithCapacity: lentext];
    ixinbuf = 0;
    
    while (true) {
        if (ixtext >= lentext) {
            break;
        }
        
        ch = tempcstring [ixtext++];
        flignore = false;
        
        if ((ch >= 'A') && (ch <= 'Z')) {
            ch = ch - 'A';
        } else if ((ch >= 'a') && (ch <= 'z')) {
            ch = ch - 'a' + 26;
        } else if ((ch >= '0') && (ch <= '9')) {
            ch = ch - '0' + 52;
        } else if (ch == '+') {
            ch = 62;
        } else if (ch == '=') {
            flendtext = true;
        } else if (ch == '/') {
            ch = 63;
        } else {
            flignore = true;
        }
        
        if (!flignore) {
            short ctcharsinbuf = 3;
            Boolean flbreak = false;
            
            if (flendtext) {
                if (ixinbuf == 0) {
                    break;
                }
                
                if ((ixinbuf == 1) || (ixinbuf == 2)) {
                    ctcharsinbuf = 1;
                } else {
                    ctcharsinbuf = 2;
                }
                
                ixinbuf = 3;
                flbreak = true;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4) {
                ixinbuf = 0;
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                for (i = 0; i < ctcharsinbuf; i++) {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak) {
                break;
            }
        }
    }
    
    return theData;
}


@end
