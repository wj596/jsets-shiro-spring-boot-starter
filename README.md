# jsets-shiro-spring-boot-starter

[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

springboot环境中使用shiro大都是通过shiro-spring进行的,虽然不是太复杂，但无法做到spring-boot-starter风格的开箱即用。

开发实践中经常使用的功能如验证码、密码错误次数限制、账号唯一用户登陆、动态URL过滤、无状态鉴权支持等功能还是需要对shiro的原理和认证体系有较为深入的理解才能进行扩展。

jsets-shiro-spring-boot-starter对这些进行了封装和自动导入，使用少量的配置就可以立即应用到项目中。

目前提供的功能：

1、spring-boot-starter风格开箱即用

2、集成jcaptcha验证码

3、密码输入错误重试次数限制。

4、账号唯一用户登陆，一个账号只允许一个用户登陆。

5、REDIS缓存，认证\授权数据缓存同步。

6、动态URL过滤规则。

7、无状态认证授权，共存有状态和无状态两种鉴权方式，支持JWT(JSON WEB TOKEN)、HMAC(哈希消息认证码)两种协议。

8、在线SESSION管理。

计划提供的功能：

1、CAS单点登陆集成

2、oauth2.0支持

#### 快速开始

#### 使用说明
