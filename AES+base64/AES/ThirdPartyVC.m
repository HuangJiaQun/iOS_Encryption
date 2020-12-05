
#import "ThirdPartyVC.h"

@interface ThirdPartyVC ()

@end

@implementation ThirdPartyVC

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    //<加密方式一：AES+base64>，加密的密文足够长。
    
    //加密并进行base64编码(双重加密)，然后打印密文
    NSString *str = [self encryptText:@"123"].base64EncodedString;
    NSLog(@"%@",str);
    
    //解密并打印明文
    NSData *data = [str base64DecodedData];
    NSString *newS = [self decryptText:data];
    NSLog(@"%@", newS);
    
    
    //<加密方式二：base64>，加密的密文比较短。
    
    NSString *s = @"123";//明文
    NSString *ss = [s base64EncodedString];//base64加密
    NSLog(@"%@", ss);//打印密文
    
    NSString *newSS = [ss base64DecodedString];//base64解密
    NSLog(@"%@", newSS);//打印明文
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/
//加密
-(NSData*) encryptText:(NSString*)text {
    CCCryptorStatus status = kCCSuccess;
    NSData* result = [[text dataUsingEncoding:NSUTF8StringEncoding]
                      dataEncryptedUsingAlgorithm:kCCAlgorithmAES128
                      key:@"4NRB426266F63333"
                      initializationVector:nil
                      options:(kCCOptionPKCS7Padding|kCCOptionECBMode)
                      error:&status];
    if (status != kCCSuccess) {
        NSLog(@"加密失败:%d", status);
        return nil;
    }
    return result;
}

//解密
-(NSString*) decryptText:(NSData*)data
{
    CCCryptorStatus status = kCCSuccess;
    NSData* result = [data decryptedDataUsingAlgorithm:kCCAlgorithmAES128
                                                   key:@"4NRB426266F63333"
                                  initializationVector:nil
                                               options:(kCCOptionPKCS7Padding|kCCOptionECBMode)
                                                 error:&status];
    if (status != kCCSuccess) {
        NSLog(@"解密失败:%d", status);
        return nil;
    }
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}
@end
