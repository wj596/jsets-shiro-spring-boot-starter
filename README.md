# jsets-shiro-spring-boot-starter

[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

#### 项目说明

springboot中使用shiro大都是通过shiro-spring.jar进行的整合的,虽然不是太复杂，但是也无法做到spring-boot-starter风格的开箱即用。

项目中经常用到的功能比如：验证码、密码错误次数限制、账号唯一用户登陆、动态URL过滤规则、无状态鉴权等等，shiro还没有直接提供支持。

jsets-shiro-spring-boot-starter对这些常用的功能进行了封装和自动导入，少量的配置就可以应用在项目中。

#### 实现的功能

1、spring-boot-starter风格的开箱即用。

2、区分ajax请求和普通请求，普通请求通过跳转来响应未登陆和未授权，AJAX请求通过状态码和消息响应未登陆和未授权。

3、集成jcaptcha验证码。

4、密码输入错误，重试次数限制。

5、账号唯一用户登陆，一个账号只允许一个用户登陆。

6、redis缓存支持，认证\授权数据缓存同步。

7、动态URL过滤规则。

8、无状态认证授权支持，共存有状态和无状态两种鉴权方式，无状态鉴权支持JWT(JSON WEB TOKEN)、HMAC(哈希消息认证码)两种协议。

9、在线session管理，强制用户下线功能。

#### 计划的功能

1、cas单点登陆集成

2、oauth2.0支持

#### [快速开始](https://github.com/wj596/jsets-shiro-spring-boot-starter/wiki/A%E3%80%81%E5%BF%AB%E9%80%9F%E5%BC%80%E5%A7%8B?_blank)

#### [使用说明](https://github.com/wj596/jsets-shiro-spring-boot-starter/wiki) 

#### [示例项目](https://github.com/wj596/jsets-shiro-demo)

如果组件给您带来过帮助，请Star收藏，欢迎提出改进意见，欢迎提交改进代码。


#### [HMAC鉴权说明](https://www.jianshu.com/p/b0a577708a7b) 
#### [JWT明](https://www.jianshu.com/p/0a5d3d07a151) 
#### [组件效果预览](https://www.jianshu.com/p/40d11d18ead6) 



