//
//   Copyright 2012 Square Inc.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//


#import "SRWebSocket.h"

#if TARGET_OS_IPHONE
#define HAS_ICU
#endif

#ifdef HAS_ICU
#import <unicode/utf8.h>
#endif

#if TARGET_OS_IPHONE
#import <Endian.h>
#else
#import <CoreServices/CoreServices.h>
#endif

#import <CommonCrypto/CommonDigest.h>
#import <Security/SecRandom.h>

//6.0以上的宏，ARC GCD
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#define sr_dispatch_retain(x)
#define sr_dispatch_release(x)
#define maybe_bridge(x) ((__bridge void *) x)
#else
#define sr_dispatch_retain(x) dispatch_retain(x)
#define sr_dispatch_release(x) dispatch_release(x)
#define maybe_bridge(x) (x)
#endif

#if !__has_feature(objc_arc) 
#error SocketRocket must be compiled with ARC enabled
#endif


typedef enum  {
    SROpCodeTextFrame = 0x1,
    SROpCodeBinaryFrame = 0x2,
    // 3-7 reserved.
    SROpCodeConnectionClose = 0x8,
    SROpCodePing = 0x9,
    SROpCodePong = 0xA,
    // B-F reserved.
} SROpCode;

typedef struct {
    BOOL fin;
//  BOOL rsv1;
//  BOOL rsv2;
//  BOOL rsv3;
    uint8_t opcode;
    BOOL masked;
    uint64_t payload_length;
} frame_header;

//RFC规定的4122
//https://tools.ietf.org/html/rfc4122
//连接后的结果使用 SHA-1（160数位）FIPS.180-3 进行一个哈希操作，对哈希操作的结果，采用 base64 进行编码，然后作为服务端响应握手的一部分返回给浏览器。
static NSString *const SRWebSocketAppendToSecKeyString = @"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static inline int32_t validate_dispatch_data_partial_string(NSData *data);
static inline void SRFastLog(NSString *format, ...);

@interface NSData (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;

@end


@interface NSString (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;

@end


@interface NSURL (SRWebSocket)

// The origin isn't really applicable for a native application.
// So instead, just map ws -> http and wss -> https.
- (NSString *)SR_origin;

@end


//带runloop的 thread
@interface _SRRunLoopThread : NSThread

@property (nonatomic, readonly) NSRunLoop *runLoop;

@end


static NSString *newSHA1String(const char *bytes, size_t length) {
    uint8_t md[CC_SHA1_DIGEST_LENGTH];

    assert(length >= 0);
    assert(length <= UINT32_MAX);
    CC_SHA1(bytes, (CC_LONG)length, md);
    
    NSData *data = [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
    
    if ([data respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        return [data base64EncodedStringWithOptions:0];
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [data base64Encoding];
#pragma clang diagnostic pop
}

@implementation NSData (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;
{
    return newSHA1String(self.bytes, self.length);
}

@end


@implementation NSString (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;
{
    return newSHA1String(self.UTF8String, self.length);
}

@end

NSString *const SRWebSocketErrorDomain = @"SRWebSocketErrorDomain";
NSString *const SRHTTPResponseErrorKey = @"HTTPResponseStatusCode";

// Returns number of bytes consumed. Returning 0 means you didn't match.
// Sends bytes to callback handler;
//标识消费的数据，意思是读取的数据？
typedef size_t (^stream_scanner)(NSData *collected_data);

typedef void (^data_callback)(SRWebSocket *webSocket,  NSData *data);

//消费者对象
@interface SRIOConsumer : NSObject
{
    stream_scanner _scanner;
    data_callback _handler;
    size_t _bytesNeeded;
    BOOL _readToCurrentFrame;
    BOOL _unmaskBytes;
}
@property (nonatomic, copy, readonly) stream_scanner consumer;
@property (nonatomic, copy, readonly) data_callback handler;
@property (nonatomic, assign) size_t bytesNeeded;
@property (nonatomic, assign, readonly) BOOL readToCurrentFrame;
@property (nonatomic, assign, readonly) BOOL unmaskBytes;

@end

// This class is not thread-safe, and is expected to always be run on the same queue.
@interface SRIOConsumerPool : NSObject

- (id)initWithBufferCapacity:(NSUInteger)poolSize;

- (SRIOConsumer *)consumerWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
- (void)returnConsumer:(SRIOConsumer *)consumer;

@end

@interface SRWebSocket ()  <NSStreamDelegate>

@property (nonatomic) SRReadyState readyState;

@property (nonatomic) NSOperationQueue *delegateOperationQueue;
@property (nonatomic) dispatch_queue_t delegateDispatchQueue;

// Specifies whether SSL trust chain should NOT be evaluated.
// By default this flag is set to NO, meaning only secure SSL connections are allowed.
// For DEBUG builds this flag is ignored, and SSL connections are allowed regardless
// of the certificate trust configuration
@property (nonatomic, readwrite) BOOL allowsUntrustedSSLCertificates;

@end


@implementation SRWebSocket {
    NSInteger _webSocketVersion;
    
    NSOperationQueue *_delegateOperationQueue;
    dispatch_queue_t _delegateDispatchQueue;
    
    dispatch_queue_t _workQueue;
    NSMutableArray *_consumers;

    NSInputStream *_inputStream;
    NSOutputStream *_outputStream;
   
    NSMutableData *_readBuffer;
    NSUInteger _readBufferOffset;
 
    NSMutableData *_outputBuffer;
    NSUInteger _outputBufferOffset;

    uint8_t _currentFrameOpcode;
    size_t _currentFrameCount;
    //读取的帧数
    size_t _readOpCount;
    uint32_t _currentStringScanPosition;
    NSMutableData *_currentFrameData;
    
    NSString *_closeReason;
    //对称密钥
    NSString *_secKey;
    NSString *_basicAuthorizationString;
    
    BOOL _pinnedCertFound;
    
    uint8_t _currentReadMaskKey[4];
    size_t _currentReadMaskOffset;

    BOOL _consumerStopped;
    
    BOOL _closeWhenFinishedWriting;
    BOOL _failed;

    BOOL _secure;
    NSURLRequest *_urlRequest;

    BOOL _sentClose;
    BOOL _didFail;
    BOOL _cleanupScheduled;
    int _closeCode;
    
    BOOL _isPumping;
    
    NSMutableSet *_scheduledRunloops;
    
    // We use this to retain ourselves.
    __strong SRWebSocket *_selfRetain;
    
    NSArray *_requestedProtocols;
    SRIOConsumerPool *_consumerPool;
}

@synthesize delegate = _delegate;
@synthesize url = _url;
@synthesize readyState = _readyState;
@synthesize protocol = _protocol;

static __strong NSData *CRLFCRLF;

+ (void)initialize;
{
    CRLFCRLF = [[NSData alloc] initWithBytes:"\r\n\r\n" length:4];
}

//最终的初始化方法
- (id)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates;
{
    
    self = [super init];
    if (self) {
        assert(request.URL);
        _url = request.URL;
        _urlRequest = request;
        //是否允许非信任的证书
        _allowsUntrustedSSLCertificates = allowsUntrustedSSLCertificates;
        //拿到协议的数组
        _requestedProtocols = [protocols copy];
        
        [self _SR_commonInit];
    }
    
    return self;
}

- (id)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray *)protocols;
{
    return [self initWithURLRequest:request protocols:protocols allowsUntrustedSSLCertificates:NO];
}

- (id)initWithURLRequest:(NSURLRequest *)request;
{
    return [self initWithURLRequest:request protocols:nil];
}

- (id)initWithURL:(NSURL *)url;
{
    return [self initWithURL:url protocols:nil];
}

- (id)initWithURL:(NSURL *)url protocols:(NSArray *)protocols;
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];    
    return [self initWithURLRequest:request protocols:protocols];
}

- (id)initWithURL:(NSURL *)url protocols:(NSArray *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates;
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    return [self initWithURLRequest:request protocols:protocols allowsUntrustedSSLCertificates:allowsUntrustedSSLCertificates];
}

//初始化
- (void)_SR_commonInit;
{
    //得到url schem小写
    NSString *scheme = _url.scheme.lowercaseString;
    
    //如果不是这几种，则断言错误
    assert([scheme isEqualToString:@"ws"] || [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"]);
    
    //ssl
    if ([scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"]) {
        _secure = YES;
    }
    //标识状态为正在连接
    _readyState = SR_CONNECTING;
    
    //用户已停止？
    _consumerStopped = YES;
    //标识版本
    _webSocketVersion = 13;
    
    //初始化工作的队列，串行
    _workQueue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    
    // Going to set a specific on the queue so we can validate we're on the work queue
    //给队列设置一个标识,标识为指向自己的，上下文对象为这个队列
    dispatch_queue_set_specific(_workQueue, (__bridge void *)self, maybe_bridge(_workQueue), NULL);
    
    //设置代理queue为主队列
    _delegateDispatchQueue = dispatch_get_main_queue();
    
    //retain主队列？
    sr_dispatch_retain(_delegateDispatchQueue);
    
    //读Buffer
    _readBuffer = [[NSMutableData alloc] init];
    //输出Buffer
    _outputBuffer = [[NSMutableData alloc] init];
  
    //wtf?
    _currentFrameData = [[NSMutableData alloc] init];
    
    //消费者？
    _consumers = [[NSMutableArray alloc] init];
    
    _consumerPool = [[SRIOConsumerPool alloc] init];
    //注册的runloop
    _scheduledRunloops = [[NSMutableSet alloc] init];
    //初始化流
    [self _initializeStreams];
    
    // default handlers
}

//断言当前是_workQueue
- (void)assertOnWorkQueue;
{
    //因为设置了上下文对象，所以这里如果是在当前队列调用，则返回的是_workQueue
    //dispatch_get_specific((__bridge void *)self) 拿到当前queue的指针  判断和后者是不是相同
    assert(dispatch_get_specific((__bridge void *)self) == maybe_bridge(_workQueue));
}

- (void)dealloc
{
    _inputStream.delegate = nil;
    _outputStream.delegate = nil;

    [_inputStream close];
    [_outputStream close];
    
    if (_workQueue) {
        sr_dispatch_release(_workQueue);
        _workQueue = NULL;
    }
    
    if (_receivedHTTPHeaders) {
        CFRelease(_receivedHTTPHeaders);
        _receivedHTTPHeaders = NULL;
    }
    
    if (_delegateDispatchQueue) {
        sr_dispatch_release(_delegateDispatchQueue);
        _delegateDispatchQueue = NULL;
    }
}

#ifndef NDEBUG

- (void)setReadyState:(SRReadyState)aReadyState;
{
    assert(aReadyState > _readyState);
    _readyState = aReadyState;
}

#endif
//开始连接
- (void)open;
{
    assert(_url);
    //如果状态是正在连接，直接断言出错
    NSAssert(_readyState == SR_CONNECTING, @"Cannot call -(void)open on SRWebSocket more than once");

    //自己持有自己
    _selfRetain = self;
    //判断超时时长
    if (_urlRequest.timeoutInterval > 0)
    {
        dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, _urlRequest.timeoutInterval * NSEC_PER_SEC);
        //在超时时间执行
        dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
            //如果还在连接，报错
            if (self.readyState == SR_CONNECTING)
                [self _failWithError:[NSError errorWithDomain:@"com.squareup.SocketRocket" code:504 userInfo:@{NSLocalizedDescriptionKey: @"Timeout Connecting to Server"}]];
        });
    }
    //开始建立连接
    [self openConnection];
}

// Calls block on delegate queue
- (void)_performDelegateBlock:(dispatch_block_t)block;
{
    if (_delegateOperationQueue) {
        [_delegateOperationQueue addOperationWithBlock:block];
    } else {
        assert(_delegateDispatchQueue);
        dispatch_async(_delegateDispatchQueue, block);
    }
}

- (void)setDelegateDispatchQueue:(dispatch_queue_t)queue;
{
    if (queue) {
        sr_dispatch_retain(queue);
    }
    
    if (_delegateDispatchQueue) {
        sr_dispatch_release(_delegateDispatchQueue);
    }
    
    _delegateDispatchQueue = queue;
}

//检查握手信息
- (BOOL)_checkHandshake:(CFHTTPMessageRef)httpMessage;
{
    //是否是允许的header
    NSString *acceptHeader = CFBridgingRelease(CFHTTPMessageCopyHeaderFieldValue(httpMessage, CFSTR("Sec-WebSocket-Accept")));

    //为空则被服务器拒绝
    if (acceptHeader == nil) {
        return NO;
    }
    
    //得到
    NSString *concattedString = [_secKey stringByAppendingString:SRWebSocketAppendToSecKeyString];
    //期待accept的字符串
    NSString *expectedAccept = [concattedString stringBySHA1ThenBase64Encoding];
    
    //判断是否相同，相同就握手信息对了
    return [acceptHeader isEqualToString:expectedAccept];
}

//读完数据处理
- (void)_HTTPHeadersDidFinish;
{
    //得到resonse code
    NSInteger responseCode = CFHTTPMessageGetResponseStatusCode(_receivedHTTPHeaders);
    
    //失败code
    if (responseCode >= 400) {
        SRFastLog(@"Request failed with response code %d", responseCode);
        [self _failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2132 userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"received bad response code from server %ld", (long)responseCode], SRHTTPResponseErrorKey:@(responseCode)}]];
        return;
    }
    
    //检查握手信息
    if(![self _checkHandshake:_receivedHTTPHeaders]) {
        [self _failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2133 userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"Invalid Sec-WebSocket-Accept response"] forKey:NSLocalizedDescriptionKey]]];
        return;
    }
    
    //得到协议
    NSString *negotiatedProtocol = CFBridgingRelease(CFHTTPMessageCopyHeaderFieldValue(_receivedHTTPHeaders, CFSTR("Sec-WebSocket-Protocol")));
    if (negotiatedProtocol) {
        // Make sure we requested the protocol
        //如果请求的协议里没找到，服务端要求的协议，则失败
        if ([_requestedProtocols indexOfObject:negotiatedProtocol] == NSNotFound) {
            [self _failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2133 userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"Server specified Sec-WebSocket-Protocol that wasn't requested"] forKey:NSLocalizedDescriptionKey]]];
            return;
        }
        
        _protocol = negotiatedProtocol;
    }
    //修改状态，open
    self.readyState = SR_OPEN;
    //开始读取新的消息帧
    if (!_didFail) {
        [self _readFrameNew];
    }
    //调用已经连接的代理
    [self _performDelegateBlock:^{
        if ([self.delegate respondsToSelector:@selector(webSocketDidOpen:)]) {
            [self.delegate webSocketDidOpen:self];
        };
    }];
}


//读取http头部
- (void)_readHTTPHeader;
{
    if (_receivedHTTPHeaders == NULL) {
        //序列化的http消息
        _receivedHTTPHeaders = CFHTTPMessageCreateEmpty(NULL, NO);
    }
    
    //不停的add consumer去读数据
    [self _readUntilHeaderCompleteWithCallback:^(SRWebSocket *self,  NSData *data) {
        
        //拼接数据，拼到头部
        CFHTTPMessageAppendBytes(_receivedHTTPHeaders, (const UInt8 *)data.bytes, data.length);
        
        //判断是否接受完
        if (CFHTTPMessageIsHeaderComplete(_receivedHTTPHeaders)) {
            SRFastLog(@"Finished reading headers %@", CFBridgingRelease(CFHTTPMessageCopyAllHeaderFields(_receivedHTTPHeaders)));
            [self _HTTPHeadersDidFinish];
        } else {
            //没读完递归调
            [self _readHTTPHeader];
        }
    }];
}

//流打开成功后的操作，开始发送http请求建立连接
- (void)didConnect;
{
    SRFastLog(@"Connected");
    //创建一个http request  url
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), (__bridge CFURLRef)_url, kCFHTTPVersion1_1);
    
    // Set host first so it defaults
    //设置head, host:  url+port
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Host"), (__bridge CFStringRef)(_url.port ? [NSString stringWithFormat:@"%@:%@", _url.host, _url.port] : _url.host));
    //密钥数据（生成对称密钥）
    NSMutableData *keyBytes = [[NSMutableData alloc] initWithLength:16];
    //生成随机密钥
    SecRandomCopyBytes(kSecRandomDefault, keyBytes.length, keyBytes.mutableBytes);
    
    //根据版本用base64转码
    if ([keyBytes respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        _secKey = [keyBytes base64EncodedStringWithOptions:0];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        _secKey = [keyBytes base64Encoding];
#pragma clang diagnostic pop
    }
    
    //断言编码后长度为24
    assert([_secKey length] == 24);

    // Apply cookies if any have been provided
    //提供cookies
    NSDictionary * cookies = [NSHTTPCookie requestHeaderFieldsWithCookies:[self requestCookies]];
    for (NSString * cookieKey in cookies) {
        //拿到cookie值
        NSString * cookieValue = [cookies objectForKey:cookieKey];
        if ([cookieKey length] && [cookieValue length]) {
            //设置到request的 head里
            CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)cookieKey, (__bridge CFStringRef)cookieValue);
        }
    }
 
    // set header for http basic auth
    //设置http的基础auth,用户名密码认证
    if (_url.user.length && _url.password.length) {
        NSData *userAndPassword = [[NSString stringWithFormat:@"%@:%@", _url.user, _url.password] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *userAndPasswordBase64Encoded;
        if ([keyBytes respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
            userAndPasswordBase64Encoded = [userAndPassword base64EncodedStringWithOptions:0];
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            userAndPasswordBase64Encoded = [userAndPassword base64Encoding];
#pragma clang diagnostic pop
        }
        //编码后用户名密码
        _basicAuthorizationString = [NSString stringWithFormat:@"Basic %@", userAndPasswordBase64Encoded];
        //设置head Authorization
        CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Authorization"), (__bridge CFStringRef)_basicAuthorizationString);
    }
    //web socket规范head
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Upgrade"), CFSTR("websocket"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Connection"), CFSTR("Upgrade"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Key"), (__bridge CFStringRef)_secKey);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Version"), (__bridge CFStringRef)[NSString stringWithFormat:@"%ld", (long)_webSocketVersion]);
    
    //设置request的原始 Url
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Origin"), (__bridge CFStringRef)_url.SR_origin);
    
    //用户初始化的协议数组，可以约束websocket的一些行为
    if (_requestedProtocols) {
        CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Protocol"), (__bridge CFStringRef)[_requestedProtocols componentsJoinedByString:@", "]);
    }
    
    //吧 _urlRequest中原有的head 设置到request中去
    [_urlRequest.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
       
        CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)key, (__bridge CFStringRef)obj);
    }];
    
    //返回一个序列化 , CFBridgingRelease和 __bridge transfer一个意思， CFHTTPMessageCopySerializedMessage copy一份新的并且序列化，返回CFDataRef
    NSData *message = CFBridgingRelease(CFHTTPMessageCopySerializedMessage(request));
    
    //释放request
    CFRelease(request);

    //把这个request当成data去写
    [self _writeData:message];
    //读取http的头部
    [self _readHTTPHeader];
}

//初始化流
- (void)_initializeStreams;
{
    //断言 port值小于UINT32_MAX
    assert(_url.port.unsignedIntValue <= UINT32_MAX);
    //拿到端口
    uint32_t port = _url.port.unsignedIntValue;
    //如果端口号为0，给个默认值，http 80 https 443;
    if (port == 0) {
        if (!_secure) {
            port = 80;
        } else {
            port = 443;
        }
    }
    NSString *host = _url.host;
    
    CFReadStreamRef readStream = NULL;
    CFWriteStreamRef writeStream = NULL;
    //用host创建读写stream,Host和port就绑定在一起了
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)host, port, &readStream, &writeStream);
    
    //绑定生命周期给ARC  _outputStream = __bridge transfer
    _outputStream = CFBridgingRelease(writeStream);
    _inputStream = CFBridgingRelease(readStream);
    
    //代理设为自己
    _inputStream.delegate = self;
    _outputStream.delegate = self;
}

- (void)_updateSecureStreamOptions;
{
    //如果是安全
    if (_secure) {
        //创建ssl配置
        NSMutableDictionary *SSLOptions = [[NSMutableDictionary alloc] init];
        
        //kCFStreamSocketSecurityLevelNegotiatedSSL 可以回滚的https策略？
        [_outputStream setProperty:(__bridge id)kCFStreamSocketSecurityLevelNegotiatedSSL forKey:(__bridge id)kCFStreamPropertySocketSecurityLevel];
        
        // If we're using pinned certs, don't validate the certificate chain
        // 如果用了自签的证书？  不验证证书链
        if ([_urlRequest SR_SSLPinnedCertificates].count) {
            //只要有一个节点匹配即可
            [SSLOptions setValue:@NO forKey:(__bridge id)kCFStreamSSLValidatesCertificateChain];
        }
#if DEBUG
        //是否支持不信任的证书
        self.allowsUntrustedSSLCertificates = YES;
#endif

        if (self.allowsUntrustedSSLCertificates) {
            //不验证证书链
            [SSLOptions setValue:@NO forKey:(__bridge id)kCFStreamSSLValidatesCertificateChain];
            SRFastLog(@"Allowing connection to any root cert");
        }
        //设置给_outputStream
        [_outputStream setProperty:SSLOptions
                            forKey:(__bridge id)kCFStreamPropertySSLSettings];
    }
    //流代理
    _inputStream.delegate = self;
    _outputStream.delegate = self;
    //初始化网络类型
    [self setupNetworkServiceType:_urlRequest.networkServiceType];
}

- (void)setupNetworkServiceType:(NSURLRequestNetworkServiceType)requestNetworkServiceType
{
    NSString *networkServiceType;
    switch (requestNetworkServiceType) {
            //默认的不做任何处理
        case NSURLNetworkServiceTypeDefault:
            break;
            //VOIP,表明这个socket用于voip
        case NSURLNetworkServiceTypeVoIP: {
            networkServiceType = NSStreamNetworkServiceTypeVoIP;
#if TARGET_OS_IPHONE && __IPHONE_9_0
            
            //判断版本,8.3后用PushKit来控制，废弃了NSStreamNetworkServiceTypeVoIP
            if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_3) {
                static dispatch_once_t predicate;
                dispatch_once(&predicate, ^{
                    NSLog(@"SocketRocket: %@ - this service type is deprecated in favor of using PushKit for VoIP control", networkServiceType);
                });
            }
#endif
            break;
        }
            //视频传输
        case NSURLNetworkServiceTypeVideo:
            networkServiceType = NSStreamNetworkServiceTypeVideo;
            break;
            //后台传输
        case NSURLNetworkServiceTypeBackground:
            networkServiceType = NSStreamNetworkServiceTypeBackground;
            break;
            //声音数据
        case NSURLNetworkServiceTypeVoice:
            networkServiceType = NSStreamNetworkServiceTypeVoice;
            break;
    }
    
    if (networkServiceType != nil) {
        //设置给输入输出流
        [_inputStream setProperty:networkServiceType forKey:NSStreamNetworkServiceType];
        [_outputStream setProperty:networkServiceType forKey:NSStreamNetworkServiceType];
    }
}
//开始连接
- (void)openConnection;
{
    //更新安全、流配置
    [self _updateSecureStreamOptions];
    
    //判断有没有runloop
    if (!_scheduledRunloops.count) {
        //SR_networkRunLoop会创建一个带runloop的常驻线程，模式为NSDefaultRunLoopMode。
        [self scheduleInRunLoop:[NSRunLoop SR_networkRunLoop] forMode:NSDefaultRunLoopMode];
    }
    
    //开启输入输出流
    [_outputStream open];
    [_inputStream open];
}

- (void)scheduleInRunLoop:(NSRunLoop *)aRunLoop forMode:(NSString *)mode;
{
    [_outputStream scheduleInRunLoop:aRunLoop forMode:mode];
    [_inputStream scheduleInRunLoop:aRunLoop forMode:mode];
    
    //添加到集合里，数组
    [_scheduledRunloops addObject:@[aRunLoop, mode]];
}

- (void)unscheduleFromRunLoop:(NSRunLoop *)aRunLoop forMode:(NSString *)mode;
{
    [_outputStream removeFromRunLoop:aRunLoop forMode:mode];
    [_inputStream removeFromRunLoop:aRunLoop forMode:mode];
    
    //移除
    [_scheduledRunloops removeObject:@[aRunLoop, mode]];
}

- (void)close;
{
    [self closeWithCode:SRStatusCodeNormal reason:nil];
}
//用code来关闭
- (void)closeWithCode:(NSInteger)code reason:(NSString *)reason;
{
    assert(code);
    dispatch_async(_workQueue, ^{
        if (self.readyState == SR_CLOSING || self.readyState == SR_CLOSED) {
            return;
        }
        
        BOOL wasConnecting = self.readyState == SR_CONNECTING;
        
        self.readyState = SR_CLOSING;
        
        SRFastLog(@"Closing with code %d reason %@", code, reason);
        
        if (wasConnecting) {
            [self closeConnection];
            return;
        }

        size_t maxMsgSize = [reason maximumLengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        NSMutableData *mutablePayload = [[NSMutableData alloc] initWithLength:sizeof(uint16_t) + maxMsgSize];
        NSData *payload = mutablePayload;
        
        ((uint16_t *)mutablePayload.mutableBytes)[0] = EndianU16_BtoN(code);
        
        if (reason) {
            NSRange remainingRange = {0};
            
            NSUInteger usedLength = 0;
            
            BOOL success = [reason getBytes:(char *)mutablePayload.mutableBytes + sizeof(uint16_t) maxLength:payload.length - sizeof(uint16_t) usedLength:&usedLength encoding:NSUTF8StringEncoding options:NSStringEncodingConversionExternalRepresentation range:NSMakeRange(0, reason.length) remainingRange:&remainingRange];
            #pragma unused (success)
            
            assert(success);
            assert(remainingRange.length == 0);

            if (usedLength != maxMsgSize) {
                payload = [payload subdataWithRange:NSMakeRange(0, usedLength + sizeof(uint16_t))];
            }
        }
        
        
        [self _sendFrameWithOpcode:SROpCodeConnectionClose data:payload];
    });
}

//因为协议的错误，关闭
- (void)_closeWithProtocolError:(NSString *)message;
{
    // Need to shunt this on the _callbackQueue first to see if they received any messages 
    [self _performDelegateBlock:^{
        [self closeWithCode:SRStatusCodeProtocolError reason:message];
        dispatch_async(_workQueue, ^{
            [self closeConnection];
        });
    }];
}

//报错的方法
- (void)_failWithError:(NSError *)error;
{
    dispatch_async(_workQueue, ^{
        if (self.readyState != SR_CLOSED) {
            _failed = YES;
            [self _performDelegateBlock:^{
                if ([self.delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
                    [self.delegate webSocket:self didFailWithError:error];
                }
            }];

            self.readyState = SR_CLOSED;

            SRFastLog(@"Failing with error %@", error.localizedDescription);
            
            [self closeConnection];
            [self _scheduleCleanup];
        }
    });
}

//写数据
- (void)_writeData:(NSData *)data;
{
    //断言当前queue
    [self assertOnWorkQueue];
    //如果标记为写完成关闭，则直接返回
    if (_closeWhenFinishedWriting) {
            return;
    }
    //输出buffer拼接数据
    [_outputBuffer appendData:data];
    //开始写
    [self _pumpWriting];
}

//发送数据
- (void)send:(id)data;
{
    NSAssert(self.readyState != SR_CONNECTING, @"Invalid State: Cannot call send: until connection is open");
    // TODO: maybe not copy this for performance
    data = [data copy];
    dispatch_async(_workQueue, ^{
        //根据类型给帧类型 SROpCodeTextFrame文本，SROpCodeBinaryFrame二进制类型
        if ([data isKindOfClass:[NSString class]]) {
            [self _sendFrameWithOpcode:SROpCodeTextFrame data:[(NSString *)data dataUsingEncoding:NSUTF8StringEncoding]];
        } else if ([data isKindOfClass:[NSData class]]) {
            [self _sendFrameWithOpcode:SROpCodeBinaryFrame data:data];
        } else if (data == nil) {
            [self _sendFrameWithOpcode:SROpCodeTextFrame data:data];
        } else {
            assert(NO);
        }
    });
}

- (void)sendPing:(NSData *)data;
{
    NSAssert(self.readyState == SR_OPEN, @"Invalid State: Cannot call send: until connection is open");
    // TODO: maybe not copy this for performance
    data = [data copy] ?: [NSData data]; // It's okay for a ping to be empty
    dispatch_async(_workQueue, ^{
        [self _sendFrameWithOpcode:SROpCodePing data:data];
    });
}

- (void)handlePing:(NSData *)pingData;
{
    // Need to pingpong this off _callbackQueue first to make sure messages happen in order
    [self _performDelegateBlock:^{
        dispatch_async(_workQueue, ^{
            [self _sendFrameWithOpcode:SROpCodePong data:pingData];
        });
    }];
}

- (void)handlePong:(NSData *)pongData;
{
    SRFastLog(@"Received pong");
    [self _performDelegateBlock:^{
        if ([self.delegate respondsToSelector:@selector(webSocket:didReceivePong:)]) {
            [self.delegate webSocket:self didReceivePong:pongData];
        }
    }];
}

//回调收到消息代理
- (void)_handleMessage:(id)message
{
    SRFastLog(@"Received message");
    [self _performDelegateBlock:^{
        [self.delegate webSocket:self didReceiveMessage:message];
    }];
}


static inline BOOL closeCodeIsValid(int closeCode) {
    if (closeCode < 1000) {
        return NO;
    }
    
    if (closeCode >= 1000 && closeCode <= 1011) {
        if (closeCode == 1004 ||
            closeCode == 1005 ||
            closeCode == 1006) {
            return NO;
        }
        return YES;
    }
    
    if (closeCode >= 3000 && closeCode <= 3999) {
        return YES;
    }
    
    if (closeCode >= 4000 && closeCode <= 4999) {
        return YES;
    }

    return NO;
}

//  Note from RFC:
//
//  If there is a body, the first two
//  bytes of the body MUST be a 2-byte unsigned integer (in network byte
//  order) representing a status code with value /code/ defined in
//  Section 7.4.  Following the 2-byte integer the body MAY contain UTF-8
//  encoded data with value /reason/, the interpretation of which is not
//  defined by this specification.

- (void)handleCloseWithData:(NSData *)data;
{
    size_t dataSize = data.length;
    __block uint16_t closeCode = 0;
    
    SRFastLog(@"Received close frame");
    //关闭data
    if (dataSize == 1) {
        // TODO handle error
        [self _closeWithProtocolError:@"Payload for close must be larger than 2 bytes"];
        return;
    } else if (dataSize >= 2) {
        [data getBytes:&closeCode length:sizeof(closeCode)];
        _closeCode = EndianU16_BtoN(closeCode);
        if (!closeCodeIsValid(_closeCode)) {
            [self _closeWithProtocolError:[NSString stringWithFormat:@"Cannot have close code of %d", _closeCode]];
            return;
        }
        if (dataSize > 2) {
    
            _closeReason = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(2, dataSize - 2)] encoding:NSUTF8StringEncoding];
            if (!_closeReason) {
                [self _closeWithProtocolError:@"Close reason MUST be valid UTF-8"];
                return;
            }
        }
    } else {
        _closeCode = SRStatusNoStatusReceived;
    }
    
    [self assertOnWorkQueue];
    
    if (self.readyState == SR_OPEN) {
        [self closeWithCode:1000 reason:nil];
    }
    dispatch_async(_workQueue, ^{
        [self closeConnection];
    });
}

- (void)closeConnection;
{
    [self assertOnWorkQueue];
    SRFastLog(@"Trying to disconnect");
    _closeWhenFinishedWriting = YES;
    [self _pumpWriting];
}

//当前帧读取完成
- (void)_handleFrameWithData:(NSData *)frameData opCode:(NSInteger)opcode;
{                
    // Check that the current data is valid UTF8
    
    BOOL isControlFrame = (opcode == SROpCodePing || opcode == SROpCodePong || opcode == SROpCodeConnectionClose);
    //如果不是控制帧，就去读下一帧
    if (!isControlFrame) {
        [self _readFrameNew];
    } else {
        //继续读当前帧
        dispatch_async(_workQueue, ^{
            [self _readFrameContinue];
        });
    }
    
    //frameData will be copied before passing to handlers
    //otherwise there can be misbehaviours when value at the pointer is changed
    switch (opcode) {
        //文本类型
        case SROpCodeTextFrame: {
            if ([self.delegate respondsToSelector:@selector(webSocketShouldConvertTextFrameToString:)] && ![self.delegate webSocketShouldConvertTextFrameToString:self]) {
                //给data
                [self _handleMessage:[frameData copy]];
            } else {
                //给string
                NSString *str = [[NSString alloc] initWithData:frameData encoding:NSUTF8StringEncoding];
                //string转出错，关闭连接
                if (str == nil && frameData) {
                    [self closeWithCode:SRStatusCodeInvalidUTF8 reason:@"Text frames must be valid UTF-8"];
                    dispatch_async(_workQueue, ^{
                        [self closeConnection];
                    });
                    return;
                }
                //回调
                [self _handleMessage:str];
            }
            break;
        }
        case SROpCodeBinaryFrame:
            //回调data
            [self _handleMessage:[frameData copy]];
            break;
        case SROpCodeConnectionClose:
            //关闭data
            [self handleCloseWithData:[frameData copy]];
            break;
        case SROpCodePing:
            [self handlePing:[frameData copy]];
            break;
        case SROpCodePong:
            [self handlePong:[frameData copy]];
            break;
        default:
            //关闭
            [self _closeWithProtocolError:[NSString stringWithFormat:@"Unknown opcode %ld", (long)opcode]];
            // TODO: Handle invalid opcode
            break;
    }
}

//处理数据帧
- (void)_handleFrameHeader:(frame_header)frame_header curData:(NSData *)curData;
{
    assert(frame_header.opcode != 0);
    
    if (self.readyState == SR_CLOSED) {
        return;
    }
    
    
    BOOL isControlFrame = (frame_header.opcode == SROpCodePing || frame_header.opcode == SROpCodePong || frame_header.opcode == SROpCodeConnectionClose);
    
    if (isControlFrame && !frame_header.fin) {
        [self _closeWithProtocolError:@"Fragmented control frames not allowed"];
        return;
    }
    
    if (isControlFrame && frame_header.payload_length >= 126) {
        [self _closeWithProtocolError:@"Control frames cannot have payloads larger than 126 bytes"];
        return;
    }
    //如果不是控制帧
    if (!isControlFrame) {
        //等于头部的opcode
        _currentFrameOpcode = frame_header.opcode;
        _currentFrameCount += 1;
    }
    //如果数据长度为0
    if (frame_header.payload_length == 0) {
        if (isControlFrame) {
            //读完回调
            [self _handleFrameWithData:curData opCode:frame_header.opcode];
        } else {
            if (frame_header.fin) {
                //读完回调
                [self _handleFrameWithData:_currentFrameData opCode:frame_header.opcode];
            } else {
                // TODO add assert that opcode is not a control;
                //开始读取数据
                [self _readFrameContinue];
            }
        }
    } else {
        //断言帧长度小于 SIZE_T_MAX
        assert(frame_header.payload_length <= SIZE_T_MAX);
        //添加consumer ,去读payload长度
        [self _addConsumerWithDataLength:(size_t)frame_header.payload_length callback:^(SRWebSocket *self, NSData *newData) {
            //读完回调
            if (isControlFrame) {
                [self _handleFrameWithData:newData opCode:frame_header.opcode];
            } else {
                //如果有fin,读完回调
                if (frame_header.fin) {
                    [self _handleFrameWithData:self->_currentFrameData opCode:frame_header.opcode];
                } else {
                    // TODO add assert that opcode is not a control;
                    //继续读消息帧
                    [self _readFrameContinue];
                }
                
            }
        } readToCurrentFrame:!isControlFrame unmaskBytes:frame_header.masked];
    }
}

/* From RFC:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
 */

/*
 FIN      1bit 表示信息的最后一帧，flag，也就是标记符
 RSV 1-3  1bit each 以后备用的 默认都为 0
 Opcode   4bit 帧类型，稍后细说
 Mask     1bit 掩码，是否加密数据，默认必须置为1 （这里很蛋疼）
 Payload  7bit 数据的长度  (2^7 最大到128？)
 Masking-key      1 or 4 bit 掩码   //用来加密？
 Payload data     (x + y) bytes 数据 //
 Extension data   x bytes  扩展数据
 Application data y bytes  程序数据
 */

static const uint8_t SRFinMask          = 0x80;
static const uint8_t SROpCodeMask       = 0x0F;
static const uint8_t SRRsvMask          = 0x70;
static const uint8_t SRMaskMask         = 0x80;
static const uint8_t SRPayloadLenMask   = 0x7F;


//开始读取当前消息帧
- (void)_readFrameContinue;
{
    //断言要么都为空，要么都有值
    assert((_currentFrameCount == 0 && _currentFrameOpcode == 0) || (_currentFrameCount > 0 && _currentFrameOpcode > 0));
    //添加一个consumer，数据长度为2字节 frame_header 2个字节
    [self _addConsumerWithDataLength:2 callback:^(SRWebSocket *self, NSData *data) {
        
        //
        __block frame_header header = {0};
        
        const uint8_t *headerBuffer = data.bytes;
        assert(data.length >= 2);
        
        //判断第一帧 FIN
        if (headerBuffer[0] & SRRsvMask) {
            [self _closeWithProtocolError:@"Server used RSV bits"];
            return;
        }
        //得到Qpcode
        uint8_t receivedOpcode = (SROpCodeMask & headerBuffer[0]);
        
        //判断帧类型，是否是指定的控制帧
        BOOL isControlFrame = (receivedOpcode == SROpCodePing || receivedOpcode == SROpCodePong || receivedOpcode == SROpCodeConnectionClose);
        
        //如果不是指定帧，而且receivedOpcode不等于0，而且_currentFrameCount消息帧大于0，错误关闭
        if (!isControlFrame && receivedOpcode != 0 && self->_currentFrameCount > 0) {
            [self _closeWithProtocolError:@"all data frames after the initial data frame must have opcode 0"];
            return;
        }
        // 没消息
        if (receivedOpcode == 0 && self->_currentFrameCount == 0) {
            [self _closeWithProtocolError:@"cannot continue a message"];
            return;
        }
        
        //正常读取
        //得到opcode
        header.opcode = receivedOpcode == 0 ? self->_currentFrameOpcode : receivedOpcode;
        //得到fin
        header.fin = !!(SRFinMask & headerBuffer[0]);
        
        //得到Mask
        header.masked = !!(SRMaskMask & headerBuffer[1]);
        //得到数据长度
        header.payload_length = SRPayloadLenMask & headerBuffer[1];
        
        headerBuffer = NULL;
        
        //如果是带掩码的，则报错，因为客户端是无法得知掩码的值得。
        if (header.masked) {
            [self _closeWithProtocolError:@"Client must receive unmasked data"];
        }
        
        size_t extra_bytes_needed = header.masked ? sizeof(_currentReadMaskKey) : 0;
        //得到长度
        if (header.payload_length == 126) {
            extra_bytes_needed += sizeof(uint16_t);
        } else if (header.payload_length == 127) {
            extra_bytes_needed += sizeof(uint64_t);
        }
        
        //如果多余的需要的bytes为0
        if (extra_bytes_needed == 0) {
            //
            [self _handleFrameHeader:header curData:self->_currentFrameData];
        } else {
            //读取payload
            [self _addConsumerWithDataLength:extra_bytes_needed callback:^(SRWebSocket *self, NSData *data) {
                
                size_t mapped_size = data.length;
                #pragma unused (mapped_size)
                const void *mapped_buffer = data.bytes;
                size_t offset = 0;
                
                if (header.payload_length == 126) {
                    assert(mapped_size >= sizeof(uint16_t));
                    uint16_t newLen = EndianU16_BtoN(*(uint16_t *)(mapped_buffer));
                    header.payload_length = newLen;
                    offset += sizeof(uint16_t);
                } else if (header.payload_length == 127) {
                    assert(mapped_size >= sizeof(uint64_t));
                    header.payload_length = EndianU64_BtoN(*(uint64_t *)(mapped_buffer));
                    offset += sizeof(uint64_t);
                } else {
                    assert(header.payload_length < 126 && header.payload_length >= 0);
                }
                
                if (header.masked) {
                    assert(mapped_size >= sizeof(_currentReadMaskOffset) + offset);
                    memcpy(self->_currentReadMaskKey, ((uint8_t *)mapped_buffer) + offset, sizeof(self->_currentReadMaskKey));
                }
                //把已读到的数据，和header传出去
                [self _handleFrameHeader:header curData:self->_currentFrameData];
            } readToCurrentFrame:NO unmaskBytes:NO];
        }
    } readToCurrentFrame:NO unmaskBytes:NO];
}

//读取新的消息帧
- (void)_readFrameNew;
{
    dispatch_async(_workQueue, ^{
        //清空上一帧的
        [_currentFrameData setLength:0];
        
        _currentFrameOpcode = 0;
        _currentFrameCount = 0;
        _readOpCount = 0;
        _currentStringScanPosition = 0;
        //继续读取
        [self _readFrameContinue];
    });
}

//开始写
- (void)_pumpWriting;
{
    //断言queue
    [self assertOnWorkQueue];
    
    //得到输出的buffer长度
    NSUInteger dataLength = _outputBuffer.length;
    //如果有没写完的数据而且输出流还有空间
    if (dataLength - _outputBufferOffset > 0 && _outputStream.hasSpaceAvailable) {
       
        //写入，并获取长度
        //写入进去，就会直接发送给对方了！这一步send
        NSInteger bytesWritten = [_outputStream write:_outputBuffer.bytes + _outputBufferOffset maxLength:dataLength - _outputBufferOffset];
        //写入错误
        if (bytesWritten == -1) {
            [self _failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2145 userInfo:[NSDictionary dictionaryWithObject:@"Error writing to stream" forKey:NSLocalizedDescriptionKey]]];
             return;
        }
        //加上写入长度
        _outputBufferOffset += bytesWritten;
        
        //释放掉一部分已经写完的内存
        if (_outputBufferOffset > 4096 && _outputBufferOffset > (_outputBuffer.length >> 1)) {
            _outputBuffer = [[NSMutableData alloc] initWithBytes:(char *)_outputBuffer.bytes + _outputBufferOffset length:_outputBuffer.length - _outputBufferOffset];
            _outputBufferOffset = 0;
        }
    }
    //如果关闭当完成写，输出的bufeer - 偏移量 = 0，
    if (_closeWhenFinishedWriting && 
        _outputBuffer.length - _outputBufferOffset == 0 && 
        (_inputStream.streamStatus != NSStreamStatusNotOpen &&
         _inputStream.streamStatus != NSStreamStatusClosed) &&
        !_sentClose) {
        
        ///发送关闭
        _sentClose = YES;
        
        //关闭输入输出流
        @synchronized(self) {
            [_outputStream close];
            [_inputStream close];
            
            //移除runloop
            for (NSArray *runLoop in [_scheduledRunloops copy]) {
                [self unscheduleFromRunLoop:[runLoop objectAtIndex:0] forMode:[runLoop objectAtIndex:1]];
            }
        }
        
        if (!_failed) {
            //调用关闭代理
            [self _performDelegateBlock:^{
                if ([self.delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                    [self.delegate webSocket:self didCloseWithCode:_closeCode reason:_closeReason wasClean:YES];
                }
            }];
        }
        //清除注册
        [self _scheduleCleanup];
    }
}

//指定数据读取
- (void)_addConsumerWithScanner:(stream_scanner)consumer callback:(data_callback)callback;
{
    [self assertOnWorkQueue];
    [self _addConsumerWithScanner:consumer callback:callback dataLength:0];
}

//添加消费者，用一个指定的长度，是否读到当前帧
- (void)_addConsumerWithDataLength:(size_t)dataLength callback:(data_callback)callback readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{   
    [self assertOnWorkQueue];
    assert(dataLength);
    //添加到消费者队列去
    [_consumers addObject:[_consumerPool consumerWithScanner:nil handler:callback bytesNeeded:dataLength readToCurrentFrame:readToCurrentFrame unmaskBytes:unmaskBytes]];
    [self _pumpScanner];
}

- (void)_addConsumerWithScanner:(stream_scanner)consumer callback:(data_callback)callback dataLength:(size_t)dataLength;
{    
    [self assertOnWorkQueue];
    [_consumers addObject:[_consumerPool consumerWithScanner:consumer handler:callback bytesNeeded:dataLength readToCurrentFrame:NO unmaskBytes:NO]];
    [self _pumpScanner];
}


- (void)_scheduleCleanup
{
    //用@synchronized来同步？
    @synchronized(self) {
        if (_cleanupScheduled) {
            return;
        }
        
        _cleanupScheduled = YES;
        
        // Cleanup NSStream delegate's in the same RunLoop used by the streams themselves:
        // This way we'll prevent race conditions between handleEvent and SRWebsocket's dealloc
        NSTimer *timer = [NSTimer timerWithTimeInterval:(0.0f) target:self selector:@selector(_cleanupSelfReference:) userInfo:nil repeats:NO];
        [[NSRunLoop SR_networkRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
    }
}

- (void)_cleanupSelfReference:(NSTimer *)timer
{
    @synchronized(self) {
        //清除代理和流
        // Nuke NSStream delegate's
        _inputStream.delegate = nil;
        _outputStream.delegate = nil;
        
        // Remove the streams, right now, from the networkRunLoop
        [_inputStream close];
        [_outputStream close];
    }
    
    // Cleanup selfRetain in the same GCD queue as usual
    // 断开对自己的引用
    dispatch_async(_workQueue, ^{
        _selfRetain = nil;
    });
}


static const char CRLFCRLFBytes[] = {'\r', '\n', '\r', '\n'};

//读取CRLFCRLFBytes,直到回调回来
- (void)_readUntilHeaderCompleteWithCallback:(data_callback)dataHandler;
{
    [self _readUntilBytes:CRLFCRLFBytes length:sizeof(CRLFCRLFBytes) callback:dataHandler];
}

//读取数据 CRLFCRLFBytes，边界符
- (void)_readUntilBytes:(const void *)bytes length:(size_t)length callback:(data_callback)dataHandler;
{
    // TODO optimize so this can continue from where we last searched
    
    //消费者需要消费的数据大小
    stream_scanner consumer = ^size_t(NSData *data) {
        __block size_t found_size = 0;
        __block size_t match_count = 0;
        //得到数据长度
        size_t size = data.length;
        //得到数据指针
        const unsigned char *buffer = data.bytes;
        for (size_t i = 0; i < size; i++ ) {
            //匹配字符
            if (((const unsigned char *)buffer)[i] == ((const unsigned char *)bytes)[match_count]) {
                //匹配数+1
                match_count += 1;
                //如果匹配了
                if (match_count == length) {
                    //读取数据长度等于 i+ 1
                    found_size = i + 1;
                    break;
                }
            } else {
                match_count = 0;
            }
        }
        //返回要读取数据的长度，没匹配成功就是0
        return found_size;
    };
    [self _addConsumerWithScanner:consumer callback:dataHandler];
}


// Returns true if did work
//判断当前是否正在工作
- (BOOL)_innerPumpScanner {
    
    //正在工作的标记
    BOOL didWork = NO;
    //如果就绪状态为已关闭 返回NO
    if (self.readyState >= SR_CLOSED) {
        return didWork;
    }
    //如果消费者为空，返回NO
    if (!_consumers.count) {
        return didWork;
    }
    
    //读取的buffer长度 - 偏移量  =  未读数据长
    size_t curSize = _readBuffer.length - _readBufferOffset;
    //如果未读为空，返回NO
    if (!curSize) {
        return didWork;
    }
    //拿到第一个消费者
    SRIOConsumer *consumer = [_consumers objectAtIndex:0];
    //得到需要的字节数
    size_t bytesNeeded = consumer.bytesNeeded;
    //
    size_t foundSize = 0;
    
    //得到本次需要读取大小
    //判断有没有consumer，来获取实际消费的数据大小
    if (consumer.consumer) {
        
        //把未读数据从readBuffer中赋值到tempView里，直接持有，非copy
        NSData *tempView = [NSData dataWithBytesNoCopy:(char *)_readBuffer.bytes + _readBufferOffset length:_readBuffer.length - _readBufferOffset freeWhenDone:NO];
        //得到消费的大小
        foundSize = consumer.consumer(tempView);
    } else {
        //断言需要字节
        assert(consumer.bytesNeeded);
        //如果未读字节大于需要字节，直接等于需要字节
        if (curSize >= bytesNeeded) {
            foundSize = bytesNeeded;
        }
        //如果为读取当前帧
        else if (consumer.readToCurrentFrame) {
            //消费大小等于当前未读字节
            foundSize = curSize;
        }
    }
    
    //得到需要读取的数据，并且释放已读的空间
    //切片
    NSData *slice = nil;
    //如果读取当前帧或者foundSize大于0
    if (consumer.readToCurrentFrame || foundSize) {
        //从已读偏移到要读的字节处
        NSRange sliceRange = NSMakeRange(_readBufferOffset, foundSize);
        //得到data
        slice = [_readBuffer subdataWithRange:sliceRange];
        //增加已读偏移
        _readBufferOffset += foundSize;
        //如果读取偏移的大小大于4096，或者读取偏移大于 1/2的buffer大小
        if (_readBufferOffset > 4096 && _readBufferOffset > (_readBuffer.length >> 1)) {
            //重新创建，释放已读那部分的data空间
            _readBuffer = [[NSMutableData alloc] initWithBytes:(char *)_readBuffer.bytes + _readBufferOffset length:_readBuffer.length - _readBufferOffset];            _readBufferOffset = 0;
        }
        
        //如果用户未掩码的数据
        if (consumer.unmaskBytes) {
            //copy切片
            NSMutableData *mutableSlice = [slice mutableCopy];
            //得到长度字节数
            NSUInteger len = mutableSlice.length;
            uint8_t *bytes = mutableSlice.mutableBytes;
            
            for (NSUInteger i = 0; i < len; i++) {
                //得到一个读取掩码key，为偏移量_currentReadMaskOffset取余_currentReadMaskKey，当前掩码key，
                //再和字节异或运算（相同为0，不同为1）
                bytes[i] = bytes[i] ^ _currentReadMaskKey[_currentReadMaskOffset % sizeof(_currentReadMaskKey)];
                //偏移量+1
                _currentReadMaskOffset += 1;
            }
            //把数据改成掩码后的
            slice = mutableSlice;
        }
        
        //如果读取当前帧
        if (consumer.readToCurrentFrame) {
            //拼接数据
            [_currentFrameData appendData:slice];
            //+1
            _readOpCount += 1;
            //判断Opcode，如果是文本帧
            if (_currentFrameOpcode == SROpCodeTextFrame) {
                // Validate UTF8 stuff.
                //得到当前帧数据的长度
                size_t currentDataSize = _currentFrameData.length;
                //如果currentDataSize 大于0
                if (_currentFrameOpcode == SROpCodeTextFrame && currentDataSize > 0) {
                    // TODO: Optimize the crap out of this.  Don't really have to copy all the data each time
                    //判断需要scan的大小
                    size_t scanSize = currentDataSize - _currentStringScanPosition;
                    //得到要sacn的data
                    NSData *scan_data = [_currentFrameData subdataWithRange:NSMakeRange(_currentStringScanPosition, scanSize)];
                    //验证数据
                    int32_t valid_utf8_size = validate_dispatch_data_partial_string(scan_data);
                    
                    //-1为错误，关闭连接
                    if (valid_utf8_size == -1) {
                        [self closeWithCode:SRStatusCodeInvalidUTF8 reason:@"Text frames must be valid UTF-8"];
                        dispatch_async(_workQueue, ^{
                            [self closeConnection];
                        });
                        return didWork;
                    } else {
                        //扫描的位置+上合法数据的size
                        _currentStringScanPosition += valid_utf8_size;
                    }
                } 
                
            }
            //需要的size - 已操作的size
            consumer.bytesNeeded -= foundSize;
            //如果还需要的字节数 = 0，移除消费者
            if (consumer.bytesNeeded == 0) {
                [_consumers removeObjectAtIndex:0];
                //回调读取完成
                consumer.handler(self, nil);
                //把要返回的consumer，先放在_consumerPool缓冲池中
                [_consumerPool returnConsumer:consumer];
                //已经工作为YES
                didWork = YES;
            }
        } else if (foundSize) {
            //移除消费者
            [_consumers removeObjectAtIndex:0];
            //回调回去当前接受到的数据
            consumer.handler(self, slice);

            [_consumerPool returnConsumer:consumer];
            didWork = YES;
        }
    }
    return didWork;
}
//开始扫描
-(void)_pumpScanner;
{
    [self assertOnWorkQueue];
    //判断是否在扫描
    if (!_isPumping) {
        _isPumping = YES;
    } else {
        return;
    }
    
    //只有为NO能走到这里，开始循环检测，可读可写数据
    while ([self _innerPumpScanner]) {
        
    }
    
    _isPumping = NO;
}

//#define NOMASK

static const size_t SRFrameHeaderOverhead = 32;

//发送帧数据
- (void)_sendFrameWithOpcode:(SROpCode)opcode data:(id)data;
{
    [self assertOnWorkQueue];
    
    if (nil == data) {
        return;
    }
    
    NSAssert([data isKindOfClass:[NSData class]] || [data isKindOfClass:[NSString class]], @"NSString or NSData");
    //得到发送数据长度
    size_t payloadLength = [data isKindOfClass:[NSString class]] ? [(NSString *)data lengthOfBytesUsingEncoding:NSUTF8StringEncoding] : [data length];
    //+上外层包裹的帧长度 32个字节？
    NSMutableData *frame = [[NSMutableData alloc] initWithLength:payloadLength + SRFrameHeaderOverhead];
    //如果没数据，则报数据太大出错
    if (!frame) {
        [self closeWithCode:SRStatusCodeMessageTooBig reason:@"Message too big"];
        return;
    }
    //得到帧指针
    uint8_t *frame_buffer = (uint8_t *)[frame mutableBytes];
    
    // set fin
    //写fin,还有opcode
    frame_buffer[0] = SRFinMask | opcode;
    
    BOOL useMask = YES;
#ifdef NOMASK
    useMask = NO;
#endif
    
    if (useMask) {
    // set the mask and header
        //设置mask
        frame_buffer[1] |= SRMaskMask;
    }
    
    size_t frame_buffer_size = 2;
    
    //得到未掩码数据
    const uint8_t *unmasked_payload = NULL;
    if ([data isKindOfClass:[NSData class]]) {
        unmasked_payload = (uint8_t *)[data bytes];
    } else if ([data isKindOfClass:[NSString class]]) {
        unmasked_payload =  (const uint8_t *)[data UTF8String];
    } else {
        return;
    }
    
    //赋值长度
    if (payloadLength < 126) {
        //取或
        frame_buffer[1] |= payloadLength;
    } else if (payloadLength <= UINT16_MAX) {
        frame_buffer[1] |= 126;
        //再加上2个字节来存储长度
        *((uint16_t *)(frame_buffer + frame_buffer_size)) = EndianU16_BtoN((uint16_t)payloadLength);
        frame_buffer_size += sizeof(uint16_t);
    } else {
        //第一位与127取或
        frame_buffer[1] |= 127;
        //再加上 8个字节来存储长度
        *((uint64_t *)(frame_buffer + frame_buffer_size)) = EndianU64_BtoN((uint64_t)payloadLength);
        frame_buffer_size += sizeof(uint64_t);
    }
    
    //如果没用掩码，直接填充数据
    if (!useMask) {
        for (size_t i = 0; i < payloadLength; i++) {
            frame_buffer[frame_buffer_size] = unmasked_payload[i];
            frame_buffer_size += 1;
        }
    } else {
        //先创建mask_key
        uint8_t *mask_key = frame_buffer + frame_buffer_size;
        SecRandomCopyBytes(kSecRandomDefault, sizeof(uint32_t), (uint8_t *)mask_key);
        frame_buffer_size += sizeof(uint32_t);
        
        // TODO: could probably optimize this with SIMD
        //存mask_key
        for (size_t i = 0; i < payloadLength; i++) {
            //加上带掩码的数据
            frame_buffer[frame_buffer_size] = unmasked_payload[i] ^ mask_key[i % sizeof(uint32_t)];
            frame_buffer_size += 1;
        }
    }

    assert(frame_buffer_size <= [frame length]);
    //设置帧长度
    frame.length = frame_buffer_size;
    
    [self _writeData:frame];
}

//开启流后，收到事件回调
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode;
{
    __weak typeof(self) weakSelf = self;
    
    // 如果是ssl,而且_pinnedCertFound 为NO，而且事件类型是有可读数据未读，或者事件类型是还有空余空间可写
    if (_secure && !_pinnedCertFound && (eventCode == NSStreamEventHasBytesAvailable || eventCode == NSStreamEventHasSpaceAvailable)) {
        
        //拿到证书
        NSArray *sslCerts = [_urlRequest SR_SSLPinnedCertificates];
        if (sslCerts) {
            //拿到流中SSL信息结构体
            SecTrustRef secTrust = (__bridge SecTrustRef)[aStream propertyForKey:(__bridge id)kCFStreamPropertySSLPeerTrust];
            if (secTrust) {
                //得到数量
                NSInteger numCerts = SecTrustGetCertificateCount(secTrust);
                
                for (NSInteger i = 0; i < numCerts && !_pinnedCertFound; i++) {
                    //拿到证书链上的证书
                    SecCertificateRef cert = SecTrustGetCertificateAtIndex(secTrust, i);
                    //得到data
                    NSData *certData = CFBridgingRelease(SecCertificateCopyData(cert));
                    
                    //从request中拿到SSL去匹配流中的
                    for (id ref in sslCerts) {
                        SecCertificateRef trustedCert = (__bridge SecCertificateRef)ref;
                        NSData *trustedCertData = CFBridgingRelease(SecCertificateCopyData(trustedCert));
                        //如果有一对匹配了，就设置为YES
                        if ([trustedCertData isEqualToData:certData]) {
                            _pinnedCertFound = YES;
                            break;
                        }
                    }
                }
            }
            //如果为NO，则验证失败，报错关闭
            if (!_pinnedCertFound) {
                dispatch_async(_workQueue, ^{
                    NSDictionary *userInfo = @{ NSLocalizedDescriptionKey : @"Invalid server cert" };
                    [weakSelf _failWithError:[NSError errorWithDomain:@"org.lolrus.SocketRocket" code:23556 userInfo:userInfo]];
                });
                return;
            } else if (aStream == _outputStream) {
                //如果流是输出流，则打开流成功
                dispatch_async(_workQueue, ^{
                    [self didConnect];
                });
            }
        }
    }
    dispatch_async(_workQueue, ^{
        [weakSelf safeHandleEvent:eventCode stream:aStream];
    });
}

//安全的处理事件
- (void)safeHandleEvent:(NSStreamEvent)eventCode stream:(NSStream *)aStream
{
        switch (eventCode) {
                //连接完成
            case NSStreamEventOpenCompleted: {
                SRFastLog(@"NSStreamEventOpenCompleted %@", aStream);
                //如果就绪状态为关闭或者正在关闭，直接返回
                if (self.readyState >= SR_CLOSING) {
                    return;
                }
                //断言_readBuffer
                assert(_readBuffer);
                
                // didConnect fires after certificate verification if we're using pinned certificates.
               
                BOOL usingPinnedCerts = [[_urlRequest SR_SSLPinnedCertificates] count] > 0;
                //如果是http，或者无自签证书，而且是正准备连接，而且aStream是输入流
                if ((!_secure || !usingPinnedCerts) && self.readyState == SR_CONNECTING && aStream == _inputStream) {
                    //连接
                    [self didConnect];
                }
                //开始写(http握手)
                [self _pumpWriting];
                //开始扫描读写
                [self _pumpScanner];
                break;
            }
            //流事件错误
            case NSStreamEventErrorOccurred: {
                SRFastLog(@"NSStreamEventErrorOccurred %@ %@", aStream, [[aStream streamError] copy]);
                /// TODO specify error better!
                [self _failWithError:aStream.streamError];
                _readBufferOffset = 0;
                [_readBuffer setLength:0];
                break;
                
            }
            //流读到末尾
            case NSStreamEventEndEncountered: {
                //扫描下，防止有未操作完的数据
                [self _pumpScanner];
                SRFastLog(@"NSStreamEventEndEncountered %@", aStream);
                //出错的话直接关闭
                if (aStream.streamError) {
                    [self _failWithError:aStream.streamError];
                } else {
                    
                    dispatch_async(_workQueue, ^{
                        if (self.readyState != SR_CLOSED) {
                            self.readyState = SR_CLOSED;
                            [self _scheduleCleanup];
                        }
                        //如果是正常关闭
                        if (!_sentClose && !_failed) {
                            _sentClose = YES;
                            // If we get closed in this state it's probably not clean because we should be sending this when we send messages
                            [self _performDelegateBlock:^{
                                if ([self.delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                                    [self.delegate webSocket:self didCloseWithCode:SRStatusCodeGoingAway reason:@"Stream end encountered" wasClean:NO];
                                }
                            }];
                        }
                    });
                }
                
                break;
            }
            //正常读取数据
            case NSStreamEventHasBytesAvailable: {
                SRFastLog(@"NSStreamEventHasBytesAvailable %@", aStream);
                const int bufferSize = 2048;
                uint8_t buffer[bufferSize];
                //如果有可读字节
                while (_inputStream.hasBytesAvailable) {
                    //读取数据，一次读2048
                    NSInteger bytes_read = [_inputStream read:buffer maxLength:bufferSize];
                    
                    if (bytes_read > 0) {
                        //拼接数据
                        [_readBuffer appendBytes:buffer length:bytes_read];
                    } else if (bytes_read < 0) {
                        //读取错误
                        [self _failWithError:_inputStream.streamError];
                    }
                    //如果读取的不等于最大的，说明读完了，跳出循环
                    if (bytes_read != bufferSize) {
                        break;
                    }
                };
                //开始扫描，看消费者什么时候消费数据
                [self _pumpScanner];
                break;
            }
            //有可写空间，一直会回调，除非写满了
            case NSStreamEventHasSpaceAvailable: {
                SRFastLog(@"NSStreamEventHasSpaceAvailable %@", aStream);
                //开始写数据
                [self _pumpWriting];
                break;
            }
                
            default:
                SRFastLog(@"(default)  %@", aStream);
                break;
        }
}

@end


@implementation SRIOConsumer

@synthesize bytesNeeded = _bytesNeeded;
@synthesize consumer = _scanner;
@synthesize handler = _handler;
@synthesize readToCurrentFrame = _readToCurrentFrame;
@synthesize unmaskBytes = _unmaskBytes;

//初始化IO消费者
- (void)setupWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{
    _scanner = [scanner copy];
    _handler = [handler copy];
    _bytesNeeded = bytesNeeded;
    _readToCurrentFrame = readToCurrentFrame;
    _unmaskBytes = unmaskBytes;
    assert(_scanner || _bytesNeeded);
}


@end


@implementation SRIOConsumerPool {
    //大小
    NSUInteger _poolSize;
    //缓冲的消费者
    NSMutableArray *_bufferedConsumers;
}

- (id)initWithBufferCapacity:(NSUInteger)poolSize;
{
    self = [super init];
    if (self) {
        _poolSize = poolSize;
        //池子大小复用消费者的数组
        _bufferedConsumers = [[NSMutableArray alloc] initWithCapacity:poolSize];
    }
    return self;
}

- (id)init
{
    //默认大小为8个
    return [self initWithBufferCapacity:8];
}

//用扫描消费  scanner block，data_callback 数据返回的Block
- (SRIOConsumer *)consumerWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{
    SRIOConsumer *consumer = nil;
    //复用
    if (_bufferedConsumers.count) {
        consumer = [_bufferedConsumers lastObject];
        [_bufferedConsumers removeLastObject];
    } else {
        consumer = [[SRIOConsumer alloc] init];
    }
    
    [consumer setupWithScanner:scanner handler:handler bytesNeeded:bytesNeeded readToCurrentFrame:readToCurrentFrame unmaskBytes:unmaskBytes];
    
    return consumer;
}

- (void)returnConsumer:(SRIOConsumer *)consumer;
{
    if (_bufferedConsumers.count < _poolSize) {
        //用完了，返回复用池
        [_bufferedConsumers addObject:consumer];
    }
}

@end



@implementation  NSURLRequest (SRCertificateAdditions)

- (NSArray *)SR_SSLPinnedCertificates;
{
    //得到SSL证书
    return [NSURLProtocol propertyForKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

@end

@implementation  NSMutableURLRequest (SRCertificateAdditions)

- (NSArray *)SR_SSLPinnedCertificates;
{
    return [NSURLProtocol propertyForKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

//设置SSL证书
- (void)setSR_SSLPinnedCertificates:(NSArray *)SR_SSLPinnedCertificates;
{
    [NSURLProtocol setProperty:SR_SSLPinnedCertificates forKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

@end

@implementation NSURL (SRWebSocket)

//ws://host:port -> (http/https)://host:port
- (NSString *)SR_origin;
{
    //小写
    NSString *scheme = [self.scheme lowercaseString];
        
    if ([scheme isEqualToString:@"wss"]) {
        scheme = @"https";
    } else if ([scheme isEqualToString:@"ws"]) {
        scheme = @"http";
    }
    
    BOOL portIsDefault = !self.port ||
                         ([scheme isEqualToString:@"http"] && self.port.integerValue == 80) ||
                         ([scheme isEqualToString:@"https"] && self.port.integerValue == 443);
    
    if (!portIsDefault) {
        return [NSString stringWithFormat:@"%@://%@:%@", scheme, self.host, self.port];
    } else {
        return [NSString stringWithFormat:@"%@://%@", scheme, self.host];
    }
}

@end

//#define SR_ENABLE_LOG
//输出模块
static inline void SRFastLog(NSString *format, ...)  {
#ifdef SR_ENABLE_LOG
    __block va_list arg_list;
    va_start (arg_list, format);
    
    NSString *formattedString = [[NSString alloc] initWithFormat:format arguments:arg_list];
    
    va_end(arg_list);
    
    NSLog(@"[SR] %@", formattedString);
#endif
}


#ifdef HAS_ICU

//iphone的处理
//验证data合法性
static inline int32_t validate_dispatch_data_partial_string(NSData *data) {
    //大于32的最大数
    if ([data length] > INT32_MAX) {
        // INT32_MAX is the limit so long as this Framework is using 32 bit ints everywhere.
        return -1;
    }
    //得到长度
    int32_t size = (int32_t)[data length];
    //得到内容指针
    const void * contents = [data bytes];
    const uint8_t *str = (const uint8_t *)contents;
    
    UChar32 codepoint = 1;
    int32_t offset = 0;
    int32_t lastOffset = 0;
    while(offset < size && codepoint > 0)  {
        //
        lastOffset = offset;
        //wtf? 指针验证差错么？
        U8_NEXT(str, offset, size, codepoint);
    }
    
    //判断 codepoint
    if (codepoint == -1) {
        // Check to see if the last byte is valid or whether it was just continuing
        if (!U8_IS_LEAD(str[lastOffset]) || U8_COUNT_TRAIL_BYTES(str[lastOffset]) + lastOffset < (int32_t)size) {
            
            size = -1;
        } else {
            uint8_t leadByte = str[lastOffset];
            U8_MASK_LEAD_BYTE(leadByte, U8_COUNT_TRAIL_BYTES(leadByte));
            
            for (int i = lastOffset + 1; i < offset; i++) {
                if (U8_IS_SINGLE(str[i]) || U8_IS_LEAD(str[i]) || !U8_IS_TRAIL(str[i])) {
                    size = -1;
                }
            }
            
            if (size != -1) {
                size = lastOffset;
            }
        }
    }
    
    if (size != -1 && ![[NSString alloc] initWithBytesNoCopy:(char *)[data bytes] length:size encoding:NSUTF8StringEncoding freeWhenDone:NO]) {
        size = -1;
    }
    
    return size;
}

#else

//非iphone的处理

// This is a hack, and probably not optimal
static inline int32_t validate_dispatch_data_partial_string(NSData *data) {
    static const int maxCodepointSize = 3;
    
    for (int i = 0; i < maxCodepointSize; i++) {
        NSString *str = [[NSString alloc] initWithBytesNoCopy:(char *)data.bytes length:data.length - i encoding:NSUTF8StringEncoding freeWhenDone:NO];
        if (str) {
            return (int32_t)data.length - i;
        }
    }
    
    return -1;
}

#endif

static _SRRunLoopThread *networkThread = nil;
static NSRunLoop *networkRunLoop = nil;

@implementation NSRunLoop (SRWebSocket)


+ (NSRunLoop *)SR_networkRunLoop {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        networkThread = [[_SRRunLoopThread alloc] init];
        networkThread.name = @"com.squareup.SocketRocket.NetworkThread";
        [networkThread start];
        //阻塞方式拿到当前runloop
        networkRunLoop = networkThread.runLoop;
    });
    
    return networkRunLoop;
}

@end


@implementation _SRRunLoopThread {
    dispatch_group_t _waitGroup;
}

@synthesize runLoop = _runLoop;

- (void)dealloc
{
    sr_dispatch_release(_waitGroup);
}

- (id)init
{
    self = [super init];
    if (self) {
        //创建一个group
        _waitGroup = dispatch_group_create();
        //等待的group里 + 1
        dispatch_group_enter(_waitGroup);
    }
    return self;
}

//线程的执行
- (void)main;
{
    @autoreleasepool {
        //初始化runloop
        _runLoop = [NSRunLoop currentRunLoop];
        //开始执行，group - 1
        dispatch_group_leave(_waitGroup);
        
        // Add an empty run loop source to prevent runloop from spinning.
        //添加一个空的runloop source，防止runloop退出
        CFRunLoopSourceContext sourceCtx = {
            .version = 0,
            .info = NULL,
            .retain = NULL,
            .release = NULL,
            .copyDescription = NULL,
            .equal = NULL,
            .hash = NULL,
            .schedule = NULL,
            .cancel = NULL,
            .perform = NULL
        };
        //创建source
        CFRunLoopSourceRef source = CFRunLoopSourceCreate(NULL, 0, &sourceCtx);
        //默认模式
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
        CFRelease(source);
        
        //一直让runloop运行在 NSDefaultRunLoopMode 模式下
        while ([_runLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]]) {
            
        }
        assert(NO);
    }
}

- (NSRunLoop *)runLoop;
{
    //阻塞的方式获取runloop，等group里的任务都完成了，才能获取到
    //确保线程开始执行的时候，拿到正确的runloop
    dispatch_group_wait(_waitGroup, DISPATCH_TIME_FOREVER);
    return _runLoop;
}

@end
