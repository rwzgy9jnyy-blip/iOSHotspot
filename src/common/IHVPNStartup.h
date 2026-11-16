#pragma once
#import <Foundation/Foundation.h>

// 配置发布需要连续稳定一小段时间；任何一次失配都会重新计时。
static inline BOOL IHVPNStartupSettled(double *since,double now,BOOL ready) {
 if(!ready){*since=0;return NO;}
 if(*since<=0)*since=now;
 return now-*since>=0.3;
}

// 仅重试本轮明确被来源模块拒绝的初始化，不重试旧会话或未知失败。
static inline BOOL IHVPNStartupRetryAllowed(NSDictionary *diagnostic,NSString *nonce,NSTimeInterval requestedAt,NSUInteger retries) {
 return retries<2&&nonce.length&&[diagnostic[@"sessionNonce"] isEqual:nonce]&&
  [diagnostic[@"time"] isKindOfClass:NSNumber.class]&&[diagnostic[@"time"] doubleValue]>0&&
  [diagnostic[@"time"] doubleValue]>=requestedAt&&
  [@[@"legacySessionNotReady",@"vpnNamed16AuthorizationRejected",@"vpnIPv4AuthorizationRejected"] containsObject:diagnostic[@"apiResult"]?:@""];
}

// 准备确认只允许当前nonce的一次重发，不能代替NAT、网桥或转发校验。
static inline BOOL IHVPNUpstreamRetryAllowed(NSDictionary *diagnostic,NSString *nonce,BOOL retried) {
 return !retried&&nonce.length&&[diagnostic[@"nonce"] isEqual:nonce]&&[diagnostic[@"vpnUpstreamPrepared"] isEqual:@YES];
}

// 同一nonce的无线重建也必须取得新一轮PF及RA确认，不能复用上轮成功位。
static inline BOOL IHVPNStartupConfigured(NSDictionary *diagnostic,NSString *nonce,NSUInteger attempt,BOOL ipv6) {
 return nonce.length&&attempt>0&&[diagnostic[@"nonce"] isEqual:nonce]&&
  [diagnostic[@"startupAttempt"] unsignedIntegerValue]==attempt&&
  [diagnostic[ipv6?@"nat66Committed":@"nat44Committed"] isEqual:@YES]&&
  (!ipv6||[diagnostic[@"raConfigurationReady"] isEqual:@YES]);
}

// 两类确认都进入关闭→稳定→开启；准备确认本身从不放行流量。
static inline NSString *IHVPNStartupRestartReason(NSDictionary *misd,NSArray<NSDictionary*> *sources,NSString *nonce,
 NSTimeInterval requestedAt,NSUInteger retries,BOOL upstreamRetried,BOOL settled) {
 if(!settled||retries>=2)return nil;
 if(IHVPNUpstreamRetryAllowed(misd,nonce,upstreamRetried))return @"vpnUpstreamPrepared";
 for(NSDictionary *source in sources)if(IHVPNStartupRetryAllowed(source,nonce,requestedAt,retries))return @"sourceAuthorizationRejected";
 return nil;
}
