//
//  NSData+AES256.h
//  DiagramDemo
//
//  Created by ZHANG LEI on 11-7-24.
//  Copyright 2011年 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

//加密解密类
@interface NSData (AES256)

//根据key加密
- (NSData *)AES256EncryptWithKey:(NSString *)key;

//根据key解密
- (NSData *)AES256DecryptWithKey:(NSString *)key;

- (NSData *)AES128EncryptWithKey:(NSString *)key;
- (NSData *)AES128DecryptWithKey:(NSString *)key;

//解密前多少字节到文件
- (BOOL)AES128DecryptWithKey:(NSString *)key withHeadBytes:(NSUInteger)headBytes toURL:(NSURL*)url;

@end
