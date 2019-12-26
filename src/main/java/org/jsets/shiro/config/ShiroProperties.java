/*
 * Copyright 2017-2018 the original author(https://github.com/wj596)
 * 
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </p>
 */
package org.jsets.shiro.config;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * shiro配置属性
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@ConfigurationProperties(prefix = "jsets.shiro" ,ignoreUnknownFields = true,ignoreInvalidFields=true)
public class ShiroProperties {

	// 默认SESSION超时时间：1小时=3600000毫秒(ms)
	protected static final Integer DEFAULT_SESSION_TIMEOUT = 3600000;
	// 默认SESSION清扫时间：1小时=3600000毫秒(ms)
	protected static final Integer DEFAULT_SESSION_VALIDATION_INTERVAL = 3600000;
	// 记住我默认时间：1天=86400000毫秒(ms)
	protected static final Integer DEFAULT_REMEMBERME_MAX_AGE = 86400000 * 7;
	// 默认HMAC签名有效期：1分钟=60000毫秒(ms)
	protected static final Integer DEFAULT_HMAC_PERIOD = 60000;

	// 默认HASH加密算法
	protected static final String DEFAULT_HASH_ALGORITHM_NAME = "MD5";
	// 默认HASH加密盐
	protected static final String DEFAULT_HASH_SALT = "A1B2C3D4efg.5679g8e7d6c5b4a_-=_)(8.";
	// 默认HASH加密迭代次数
	protected static final Integer DEFAULT_HASH_ITERATIONS = 2;
	// 默认记住我cookie加密秘钥
	protected static final String DEFAULT_REMEMBERME_SECRETKEY = "1a2b5c8e6c9e5g2s";
	// 默认JWT加密算法
	protected static final String DEFAULT_HMAC_ALGORITHM_NAME = "HmacMD5";
	// HASH加密算法
	public static final String HASH_ALGORITHM_NAME_MD5 = "MD5";
	public static final String HASH_ALGORITHM_NAME_SHA1 = "SHA-1";
	public static final String HASH_ALGORITHM_NAME_SHA256 = "SHA-256";
	public static final String HASH_ALGORITHM_NAME_SHA512 = "SHA-512";
	// HMACA签名算法
	public static final String HMAC_ALGORITHM_NAME_MD5 = "HmacMD5";// 128位
	public static final String HMAC_ALGORITHM_NAME_SHA1 = "HmacSHA1";// 126
	public static final String HMAC_ALGORITHM_NAME_SHA256 = "HmacSHA256";// 256
	public static final String HMAC_ALGORITHM_NAME_SHA512 = "HmacSHA512";// 512
	// 缓存名称
	public static final String CACHE_NAME_PASSWORD_RETRY = "shiro-passwordRetryCache";
	public static final String CACHE_NAME_KEEP_ONE_USER = "shiro-keepOneUserCache";
	public static final String CACHE_NAME_AUTHENTICATION = "shiro-authenticationCache";
	public static final String CACHE_NAME_AUTHORIZATION = "shiro-authorizationCache";
	public static final String CACHE_NAME_TOKEN_BURNERS = "shiro-tokenBurnersCache";
	// ATTRIBUTE名称
	public static final String ATTRIBUTE_SESSION_CURRENT_USER = "shiro_current_user";
	public static final String ATTRIBUTE_SESSION_CURRENT_USER_ACCOUNT = "shiro_current_user_account";
	public static final String ATTRIBUTE_SESSION_KICKOUT = "shiro_kickout_attribute";
	public static final String ATTRIBUTE_SESSION_FORCE_LOGOUT = "shiro_force_logout_attribute";
	public static final String ATTRIBUTE_REQUEST_AUTH_MESSAGE = "shiro_auth_message";
	// PARAM名称
	public static final String PARAM_JCAPTCHA = "jcaptcha";
	public static final String PARAM_HMAC_APP_ID = "hmac_app_id";
	public static final String PARAM_HMAC_TIMESTAMP = "hmac_timestamp";
	public static final String PARAM_HMAC_DIGEST = "hmac_digest";
	public static final String PARAM_JWT = "jwt";
	// 验证码为空
	public static final String MSG_CAPTCHA_EMPTY = "验证码不能为空";
	// 验证码错误
	public static final String MSG_CAPTCHA_ERROR = "验证码错误";
	// 账号密码为空
	public static final String MSG_ACCOUNT_PASSWORD_EMPTY = "账号和密码均不能为空";
	// 账号不存在
	public static final String MSG_ACCOUNT_NOT_EXIST = "账号不存在";
	// 账号异常
	public static final String MSG_ACCOUNT_EXCEPTION = "账号异常";
	// 账号或密码错误
	public static final String MSG_ACCOUNT_PASSWORD_ERROR = "账号或密码错误";
	// 密码重试错误
	public static final String MSG_PASSWORD_RETRY_ERROR = "密码输入错误 {total} 次账号将被锁定, 您还能再试 {remain} 次";
	// 验证码为空
	public static final String MSG_BURNED_TOKEN = "作废的签名(令牌)";
	// 找不到秘钥
	public static final String MSG_NO_SECRET_KEY = "找不验签秘钥";
	// 签名无效
	public static final String MSG_HMAC_ERROR = "hmac签名无效";
	// 签名过期
	public static final String MSG_HMAC_TIMEOUT = "hmac签名超时失效";
	// 令牌无效
	public static final String MSG_JWT_ERROR = "jwt无效";
	// 令牌过期
	public static final String MSG_JWT_TIMEOUT = "jwt令牌超时失效";
	// 令牌格式错误
	public static final String MSG_JWT_MALFORMED = "jwt格式错误";
	// 令牌签名无效
	public static final String MSG_JWT_SIGNATURE = "jwt签名无效";
	// REST编码-身份验证成功
	public static final String REST_CODE_AUTH_SUCCEED = "auth:succeed";
	// REST消息-身份验证成功
	public static final String REST_MESSAGE_AUTH_SUCCEED = "身份验证成功";
	// REST编码-身份验证失败
	public static final String REST_CODE_AUTH_LOGIN_ERROR = "auth:login_error";
	// REST消息-身份验证失败
	public static final String REST_MESSAGE_AUTH_LOGIN_ERROR = "身份验证失败";
	// REST编码-需要身份验证
	public static final String REST_CODE_AUTH_UNAUTHORIZED = "auth:unauthorized";
	// REST消息-需要身份验证
	public static final String REST_MESSAGE_AUTH_UNAUTHORIZED = "需要身份验证";
	// REST编码-权限不足
	public static final String REST_CODE_AUTH_FORBIDDEN = "auth:forbidden";
	// REST消息-权限不足
	public static final String REST_MESSAGE_AUTH_FORBIDDEN = "权限不足";
	// REST编码-无用户
	public static final String REST_CODE_AUTH_USER_NOT_FOUND = "auth:user_not_found";
	// REST编码-密码错误
	public static final String REST_CODE_AUTH_NO_PERMISSION = "auth:bad_password";
	// REST编码-未知错误
	public static final String REST_CODE_INTERNAL_UNKNOWN_ERROR = "internal:unknown_error";

	// pro==============
	public static final List<String> DEFAULT_IGNORED = Arrays.asList("/**/favicon.ico", "/css/**", "/js/**",
			"/images/**", "/webjars/**", "/jcaptcha.jpg");

	private boolean jcaptchaEnable = Boolean.FALSE; // 是否启用验证码
	private boolean keepOneEnabled = Boolean.FALSE; // 是否启用账号唯一用户登陆
	private boolean forceLogoutEnable = Boolean.FALSE; // 是否启用强制用户下线
	private boolean authCacheEnabled = Boolean.FALSE;// 是否启用认证授权缓存
	private boolean hmacEnabled = Boolean.FALSE; // 是否启用HMAC鉴权
	private boolean hmacBurnEnabled = Boolean.FALSE; // 是否启用HMAC签名即时失效
	private boolean jwtEnabled = Boolean.FALSE; // 是否启用JWT鉴权
	private boolean jwtBurnEnabled = Boolean.FALSE; // 是否启用JWT令牌即时失效

	private String loginUrl;// 登陆地址
	private String loginSuccessUrl;// 登陆成功地址
	private String unauthorizedUrl;// 无访问权限地址
	private String kickoutUrl;// 被踢出地址
	private String forceLogoutUrl;// 强制退出地址
	
	//sso
	private boolean jssoServer = false;// 是否jsso服务端
	private boolean jssoClient = false;// 是否jsso客户端
	private String jssoServerUrl;// jsso登陆地址
	private String jssoLoginUrl = "/j_login";// jsso登出地址
	private String jssoLogoutUrl = "/j_logout";// jsso登出地址
	private String jssoBackUrl;// jsso登陆回跳地址
	private String jssoCheckUrl = "/j_check";// jsso令牌检查URL
	private String jssoSecretKey;// jsso签名秘钥

	private Integer passwdMaxRetries = 0;// 登陆最大重试次数
	private Integer sessionTimeout = DEFAULT_SESSION_TIMEOUT;// session超时时间
	private Integer sessionValidationInterval = DEFAULT_SESSION_VALIDATION_INTERVAL;// session清扫时间

	private Integer remembermeMaxAge = DEFAULT_REMEMBERME_MAX_AGE;// rememberMe时间
	private String remembermeSecretKey = DEFAULT_REMEMBERME_SECRETKEY;// rememberMe秘钥
	private String passwdAlg = DEFAULT_HASH_ALGORITHM_NAME;// 密码算法
	private String passwdSalt = DEFAULT_HASH_SALT;// 密码HASH盐
	private Integer passwdIterations = DEFAULT_HASH_ITERATIONS;// 密码HASH次数

	private String hmacAlg = DEFAULT_HMAC_ALGORITHM_NAME;// HMAC算法
	private String hmacSecretKey;// HMAC秘钥
	private Integer hmacPeriod = DEFAULT_HMAC_PERIOD;// HMAC签名有效时间
	private String jwtSecretKey;// JWT秘钥
	private List<String> filteRules = new LinkedList<String>();// 过滤规则
	private Boolean freePasswordEnabled = false;// 启用免密认证
	
	
	private String msgCaptchaEmpty = MSG_CAPTCHA_EMPTY;// 验证码为空
	private String msgCaptchaError = MSG_CAPTCHA_ERROR;// 验证码错误
	private String msgAccountPasswordEmpty = MSG_ACCOUNT_PASSWORD_EMPTY;// 账号密码为空
	private String msgAccountNotExist = MSG_ACCOUNT_NOT_EXIST;// 账号不存在
	private String msgAccountException = MSG_ACCOUNT_EXCEPTION;// 账号异常
	private String msgAccountPasswordError = MSG_ACCOUNT_PASSWORD_ERROR;// 账号或密码错误
	private String msgPasswordRetryError = MSG_PASSWORD_RETRY_ERROR;// 密码重试错误
	private String msgHmacError = MSG_HMAC_ERROR;// 签名无效
	private String msgHmacTimeout = MSG_HMAC_TIMEOUT;// 签名过期
	private String msgJwtError = MSG_JWT_ERROR;// 令牌无效
	private String msgJwtTimeout = MSG_JWT_TIMEOUT;// 令牌过期
	private String msgJwtMalformed = MSG_JWT_MALFORMED;// 令牌格式错误
	private String msgJwtSignature = MSG_JWT_SIGNATURE;// 令牌签名无效
	
	

	public String getPasswdAlg() {
		return passwdAlg;
	}

	public void setPasswdAlg(String passwdAlg) {
		this.passwdAlg = passwdAlg;
	}

	public String getPasswdSalt() {
		return passwdSalt;
	}

	public void setPasswdSalt(String passwdSalt) {
		this.passwdSalt = passwdSalt;
	}

	public Integer getPasswdIterations() {
		return passwdIterations;
	}

	public void setPasswdIterations(Integer passwdIterations) {
		this.passwdIterations = passwdIterations;
	}

	public String getHmacAlg() {
		return hmacAlg;
	}

	public void setHmacAlg(String hmacAlg) {
		this.hmacAlg = hmacAlg;
	}

	public String getHmacSecretKey() {
		return hmacSecretKey;
	}

	public void setHmacSecretKey(String hmacSecretKey) {
		this.hmacSecretKey = hmacSecretKey;
	}

	public String getJwtSecretKey() {
		return jwtSecretKey;
	}

	public void setJwtSecretKey(String jwtSecretKey) {
		this.jwtSecretKey = jwtSecretKey;
	}

	public String getRemembermeSecretKey() {
		return remembermeSecretKey;
	}

	public void setRemembermeSecretKey(String remembermeSecretKey) {
		this.remembermeSecretKey = remembermeSecretKey;
	}

	public Integer getRemembermeMaxAge() {
		return remembermeMaxAge;
	}

	public void setRemembermeMaxAge(Integer remembermeMaxAge) {
		this.remembermeMaxAge = remembermeMaxAge;
	}

	public Integer getSessionTimeout() {
		return sessionTimeout;
	}

	public void setSessionTimeout(Integer sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}

	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public String getLoginSuccessUrl() {
		return loginSuccessUrl;
	}

	public void setLoginSuccessUrl(String loginSuccessUrl) {
		this.loginSuccessUrl = loginSuccessUrl;
	}

	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}

	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}

	public List<String> getFilteRules() {
		return filteRules;
	}

	public void setFilteRules(List<String> filteRules) {
		this.filteRules = filteRules;
	}

	public Integer getPasswdMaxRetries() {
		return passwdMaxRetries;
	}

	public void setPasswdMaxRetries(Integer passwdMaxRetries) {
		this.passwdMaxRetries = passwdMaxRetries;
	}

	public boolean isJcaptchaEnable() {
		return jcaptchaEnable;
	}

	public void setJcaptchaEnable(boolean jcaptchaEnable) {
		this.jcaptchaEnable = jcaptchaEnable;
	}

	public String getKickoutUrl() {
		return kickoutUrl;
	}

	public void setKickoutUrl(String kickoutUrl) {
		this.kickoutUrl = kickoutUrl;
	}

	public String getForceLogoutUrl() {
		return forceLogoutUrl;
	}

	public void setForceLogoutUrl(String forceLogoutUrl) {
		this.forceLogoutUrl = forceLogoutUrl;
	}

	public boolean isAuthCacheEnabled() {
		return authCacheEnabled;
	}

	public void setAuthCacheEnabled(boolean authCacheEnabled) {
		this.authCacheEnabled = authCacheEnabled;
	}

	public boolean isKeepOneEnabled() {
		return keepOneEnabled;
	}

	public void setKeepOneEnabled(boolean keepOneEnabled) {
		this.keepOneEnabled = keepOneEnabled;
	}

	public boolean isForceLogoutEnable() {
		return forceLogoutEnable;
	}

	public void setForceLogoutEnable(boolean forceLogoutEnable) {
		this.forceLogoutEnable = forceLogoutEnable;
	}

	public boolean isHmacEnabled() {
		return hmacEnabled;
	}

	public void setHmacEnabled(boolean hmacEnabled) {
		this.hmacEnabled = hmacEnabled;
	}

	public boolean isJwtEnabled() {
		return jwtEnabled;
	}

	public void setJwtEnabled(boolean jwtEnabled) {
		this.jwtEnabled = jwtEnabled;
	}

	public Integer getHmacPeriod() {
		return hmacPeriod;
	}

	public void setHmacPeriod(Integer hmacPeriod) {
		this.hmacPeriod = hmacPeriod;
	}

	public Integer getSessionValidationInterval() {
		return sessionValidationInterval;
	}

	public void setSessionValidationInterval(Integer sessionValidationInterval) {
		this.sessionValidationInterval = sessionValidationInterval;
	}

	public boolean isHmacBurnEnabled() {
		return hmacBurnEnabled;
	}

	public void setHmacBurnEnabled(boolean hmacBurnEnabled) {
		this.hmacBurnEnabled = hmacBurnEnabled;
	}

	public boolean isJwtBurnEnabled() {
		return jwtBurnEnabled;
	}

	public void setJwtBurnEnabled(boolean jwtBurnEnabled) {
		this.jwtBurnEnabled = jwtBurnEnabled;
	}

	public String getMsgCaptchaEmpty() {
		return msgCaptchaEmpty;
	}

	public void setMsgCaptchaEmpty(String msgCaptchaEmpty) {
		this.msgCaptchaEmpty = msgCaptchaEmpty;
	}

	public String getMsgCaptchaError() {
		return msgCaptchaError;
	}

	public void setMsgCaptchaError(String msgCaptchaError) {
		this.msgCaptchaError = msgCaptchaError;
	}

	public String getMsgAccountPasswordEmpty() {
		return msgAccountPasswordEmpty;
	}

	public void setMsgAccountPasswordEmpty(String msgAccountPasswordEmpty) {
		this.msgAccountPasswordEmpty = msgAccountPasswordEmpty;
	}

	public String getMsgAccountNotExist() {
		return msgAccountNotExist;
	}

	public void setMsgAccountNotExist(String msgAccountNotExist) {
		this.msgAccountNotExist = msgAccountNotExist;
	}

	public String getMsgAccountException() {
		return msgAccountException;
	}

	public void setMsgAccountException(String msgAccountException) {
		this.msgAccountException = msgAccountException;
	}

	public String getMsgAccountPasswordError() {
		return msgAccountPasswordError;
	}

	public void setMsgAccountPasswordError(String msgAccountPasswordError) {
		this.msgAccountPasswordError = msgAccountPasswordError;
	}

	public String getMsgPasswordRetryError() {
		return msgPasswordRetryError;
	}

	public void setMsgPasswordRetryError(String msgPasswordRetryError) {
		this.msgPasswordRetryError = msgPasswordRetryError;
	}
	public String getMsgHmacError() {
		return msgHmacError;
	}
	public void setMsgHmacError(String msgHmacError) {
		this.msgHmacError = msgHmacError;
	}
	public String getMsgHmacTimeout() {
		return msgHmacTimeout;
	}
	public void setMsgHmacTimeout(String msgHmacTimeout) {
		this.msgHmacTimeout = msgHmacTimeout;
	}
	public String getMsgJwtError() {
		return msgJwtError;
	}
	public void setMsgJwtError(String msgJwtError) {
		this.msgJwtError = msgJwtError;
	}
	public String getMsgJwtTimeout() {
		return msgJwtTimeout;
	}
	public void setMsgJwtTimeout(String msgJwtTimeout) {
		this.msgJwtTimeout = msgJwtTimeout;
	}
	public String getMsgJwtMalformed() {
		return msgJwtMalformed;
	}
	public void setMsgJwtMalformed(String msgJwtMalformed) {
		this.msgJwtMalformed = msgJwtMalformed;
	}
	public String getMsgJwtSignature() {
		return msgJwtSignature;
	}
	public void setMsgJwtSignature(String msgJwtSignature) {
		this.msgJwtSignature = msgJwtSignature;
	}
	public String getJssoServerUrl() {
		return jssoServerUrl;
	}
	public void setJssoServerUrl(String jssoServerUrl) {
		this.jssoServerUrl = jssoServerUrl;
	}

	public String getJssoBackUrl() {
		return jssoBackUrl;
	}
	public void setJssoBackUrl(String jssoBackUrl) {
		this.jssoBackUrl = jssoBackUrl;
	}

	public String getJssoCheckUrl() {
		return jssoCheckUrl;
	}
	public void setJssoCheckUrl(String jssoCheckUrl) {
		this.jssoCheckUrl = jssoCheckUrl;
	}
	
	public String getJssoSecretKey() {
		return jssoSecretKey;
	}
	public void setJssoSecretKey(String jssoSecretKey) {
		this.jssoSecretKey = jssoSecretKey;
	}

	public boolean isJssoServer() {
		return jssoServer;
	}
	public void setJssoServer(boolean jssoServer) {
		this.jssoServer = jssoServer;
	}
	public String getJssoLogoutUrl() {
		return jssoLogoutUrl;
	}
	public void setJssoLogoutUrl(String jssoLogoutUrl) {
		this.jssoLogoutUrl = jssoLogoutUrl;
	}

	public boolean isJssoClient() {
		return jssoClient;
	}

	public void setJssoClient(boolean jssoClient) {
		this.jssoClient = jssoClient;
	}
	public String getJssoLoginUrl() {
		return jssoLoginUrl;
	}

	public void setJssoLoginUrl(String jssoLoginUrl) {
		this.jssoLoginUrl = jssoLoginUrl;
	}

	public boolean isFreePasswordEnabled() {
		return freePasswordEnabled;
	}

	public void setFreePasswordEnabled(boolean freePasswordEnabled) {
		this.freePasswordEnabled = freePasswordEnabled;
	}
	
	
}