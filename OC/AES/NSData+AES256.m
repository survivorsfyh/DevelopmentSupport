//
//  NSData+AES256.m
//  DiagramDemo
//
//  Created by ZHANG LEI on 11-7-24.
//  Copyright 2011年 __MyCompanyName__. All rights reserved.
//

#import "NSData+AES256.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (AES256)

- (NSData *)AES256EncryptWithKey:(NSString *)key { 
    
	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
	char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
	NSUInteger dataLength = [self length];
    
	//See the doc: For block ciphers, the output size will always be less than or 
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
	
	size_t numBytesEncrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,//kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);            
	if (cryptStatus == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
	}
    
	free(buffer); //free the buffer;
    
    
    
	return nil;
  }

- (NSData *)AES256DecryptWithKey:(NSString *)key {
    
	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
	char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
	NSUInteger dataLength = [self length];
	
	//See the doc: For block ciphers, the output size will always be less than or 
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
	
	size_t numBytesDecrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,//,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
	
	if (cryptStatus == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
	}
	
	free(buffer); //free the buffer;
    
	return nil;
}
- (NSData *)AES128EncryptWithKey:(NSString *)key{//加密
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,kCCOptionPKCS7Padding | kCCOptionECBMode,keyPtr, kCCKeySizeAES128,NULL,[self bytes], dataLength,buffer, bufferSize,&numBytesEncrypted);
        
   
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}

- (NSData *)AES128DecryptWithKey:(NSString *)key{//解密
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,kCCOptionPKCS7Padding | kCCOptionECBMode,keyPtr, kCCKeySizeAES128,NULL,[self bytes], dataLength,buffer, bufferSize,&numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

- (BOOL)AES128DecryptWithKey:(NSString *)key withHeadBytes:(NSUInteger)headBytes toURL:(NSURL*)url
{
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    //    NSUInteger dataLength = [self length];
    //    输入缓存
    size_t bufferSize = headBytes;
    void *bufferIn = malloc(bufferSize);
    [self getBytes:bufferIn length:headBytes];
    //    输出缓存
    bufferSize = headBytes + kCCBlockSizeAES128;
    void *bufferOut = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,kCCOptionPKCS7Padding | kCCOptionECBMode,keyPtr, kCCKeySizeAES128,NULL,bufferIn, headBytes,bufferOut, bufferSize,&numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSOutputStream *outPutStream = [NSOutputStream outputStreamWithURL:url append:NO];
        [outPutStream open];
        NSInteger bytesWrittenSoFar = 0;
        NSInteger       bytesWritten;
        //        写入加密后的字节
        do {
            bytesWritten = [outPutStream write:&bufferOut[bytesWrittenSoFar] maxLength:numBytesDecrypted - bytesWrittenSoFar];
            assert(bytesWritten != 0);
            if (bytesWritten == -1) {
                free(bufferIn);
                free(bufferOut);
                return NO;
            } else {
                bytesWrittenSoFar += bytesWritten;
            }
        } while (bytesWrittenSoFar != numBytesDecrypted);
        //        写入未加密的字节
        bytesWrittenSoFar=headBytes;
        const void *unEncrytedBuffer = [self bytes];
        do {
            bytesWritten = [outPutStream write:&unEncrytedBuffer[bytesWrittenSoFar] maxLength:[self length] - bytesWrittenSoFar];
            assert(bytesWritten != 0);
            if (bytesWritten == -1) {
                free(bufferIn);
                free(bufferOut);
                return NO;
            } else {
                bytesWrittenSoFar += bytesWritten;
            }
        } while (bytesWrittenSoFar != [self length]);
        free(bufferIn);
        free(bufferOut);
        return YES;
    }
    free(bufferIn);
    free(bufferOut);
    return NO;
}
@end