
#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
NSString* const common_key = @"common_key";
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    //    <CommonCrypto/CommonCryptor.h>  //常用加解密算法，例如AES、DES等
    //    <CommonCrypto/CommonDigest.h>    //常用摘要算法, 例如MD5、SHA1等
    //    <CommonCrypto/CommonHMAC.h>   //HMAC相关算法加密
    //    <CommonCrypto/CommonKeyDerivation.h>   //PBKDF导出密钥相关.
    //    <CommonCrypto/CommonSymmetricKeywrap.h>    AES Key Wrap
    
    
    
    //    CommonCryptor文件中最上方有一段苹果对该文档的摘要、介绍说明以及如何使用的英文文档。Generic interface for symmetric encryption直译是对称加密的通用接口，包含了块加密和流加密两种类型。它们分别是AES、DES、3DES、CAST、BLOWFISH和RC2以及RC4。
    //        CommonDigest文件中包括如MD5,SHA家族等哈希摘要算法。
    //        CommonHMAC文件中包含是HMAC+MD5、HMAC+SHA1等，是HMAC算法利用哈希算法，以一个密钥和一个消息为输入，生成一个消息摘要作为输出。
    //        CommonKeyDerivation是使用PBKDF导出一个可用的密匙。
    //        CommonSymmetricKeywrap中文件名称说明是SymmetricKeywrap(对称加密加密密匙)，但是在文档中苹果官方声明目前只有AES一种对称加密算法可用.
    // Do any additional setup after loading the view.
    //    [ViewController desDecrypt:@"KGngyvlgBzBMYljzFGheK8ulTSm+OPZPKYMxQANTGuo=" str:@"huangjiaqun"];
   // NSData*str = [ViewController base64DecodedWith:@"huangjaiqun"];
    NSString *str=[ViewController desEncrypt:common_key str:@"huangjaiqun"];
    NSLog(@"%@",str);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

+ (NSString *)desEncryptWith:(NSString*)str {
    return [self desEncrypt:common_key str:str];
}

+ (NSString *)desDecryptWith:(NSString*)str {
    return [self desDecrypt:common_key str:str];
}

//接口中有着加解密处理方式的选择->CCOperation，分别为kCCEncrypt加密以及kCCDecrypt解密。 //kCCEncrypt | KCCDecrypt  加密 | 解密

//加密
+ (NSString *)desEncrypt:(NSString*)key str:(NSString*)str {
    return [self doCipher:str key:key context:kCCEncrypt];
}

// 解密
+ (NSString *)desDecrypt:(NSString*)key str:(NSString*)str{
    return [self doCipher:str key:key context:kCCDecrypt];
}

//base64加密
+ (NSData*)base64DecodedWith:(NSString*)str {
    //NSMutableData*data=[[NSMutableData alloc]initWithBase64EncodedString:str options:0];
    NSData *data=[str dataUsingEncoding:NSUTF8StringEncoding];
    return [data base64EncodedDataWithOptions:0];
    
}

//CCOperation加解密处理方式
+ (NSString *)doCipher:(NSString *)sTextIn key:(NSString *)sKey
               context:(CCOperation)encryptOrDecrypt {
    
    NSMutableData * dTextIn=nil;
    
    if (encryptOrDecrypt == kCCDecrypt) {
        dTextIn = (NSMutableData*)[self base64DecodedWith:sTextIn];
    }
    else{
        dTextIn = [[sTextIn dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    
    //加密key /* DES */ kCCBlockSizeDES           = 8,密匙长度
    NSMutableData * dKey = [[sKey dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [dKey setLength:kCCBlockSizeDES];
    
    uint8_t *bufferPtr1 = NULL;
    
    size_t bufferPtrSize1 = 0;
    
    size_t movedBytes1 = 0;
    //加密后的长度
    bufferPtrSize1 = ([sTextIn length] + kCCKeySizeDES) & ~(kCCKeySizeDES -1);
    
    bufferPtr1 = malloc(bufferPtrSize1 * sizeof(uint8_t));
    
    memset((void *)bufferPtr1, 0x00, bufferPtrSize1);
    //CCCryptor()函数其实是基于第一种模式下的二次封装，是一个单次执行加解密操作的函数
    CCCrypt(encryptOrDecrypt, // CCOperation op
            kCCAlgorithmDES, // CCAlgorithm alg 加密方法
            kCCOptionPKCS7Padding, // CCOptions options 填补方式以 kCCOptionPKCS7Padding 为例.若使用ECB模式，则为kCCOptionPKCS7Padding | kCCOptionECBMode
            [dKey bytes], // const void *key
            [dKey length], // size_t keyLength
            [dKey bytes], // const void *iv
            [dTextIn bytes], // const void *dataIn
            [dTextIn length],  // size_t dataInLength
            (void *)bufferPtr1, // void *dataOut
            bufferPtrSize1,     // size_t dataOutAvailable
            &movedBytes1);      // size_t *dataOutMoved
    
    NSString * sResult=nil;
    if (encryptOrDecrypt == kCCDecrypt){
        sResult = [[ NSString alloc] initWithData:[NSData dataWithBytes:bufferPtr1
                                                                 length:movedBytes1] encoding:NSUTF8StringEncoding];
    } else {
        //加密
        NSData *dResult = [NSData dataWithBytes:bufferPtr1 length:movedBytes1];
        sResult = [dResult base64EncodedStringWithOptions:0];
    }
    
    free(bufferPtr1);
    return sResult;
}


@end
