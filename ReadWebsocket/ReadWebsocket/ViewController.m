//
//  ViewController.m
//  ReadWebsocket
//
//  Created by tyh on 2017/3/27.
//  Copyright © 2017年 tyh. All rights reserved.
//

#import "ViewController.h"
#import "SRWebSocket.h"

@interface ViewController ()<SRWebSocketDelegate>
{
    SRWebSocket *_socket;
}
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self connectServer:@"localhost" port:@"3000"];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

//初始化socket并且连接
- (void)connectServer:(NSString *)server port:(NSString *)port
{
    
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"ws://%@:%@",server,port]]];
    _socket = [[SRWebSocket alloc] initWithURLRequest:request];
    _socket.delegate = self;
    [_socket open];
}

- (void)webSocket:(SRWebSocket *)webSocket didReceiveMessage:(id)message
{

}
- (void)webSocketDidOpen:(SRWebSocket *)webSocket
{

}
- (void)webSocket:(SRWebSocket *)webSocket didFailWithError:(NSError *)error
{

}
- (void)webSocket:(SRWebSocket *)webSocket didCloseWithCode:(NSInteger)code reason:(NSString *)reason wasClean:(BOOL)wasClean
{

}
- (void)webSocket:(SRWebSocket *)webSocket didReceivePong:(NSData *)pongPayload
{

}

@end
