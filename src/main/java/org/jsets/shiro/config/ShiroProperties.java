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
@ConfigurationProperties(prefix = "jsets.shiro")
public class ShiroProperties {

	public static final String HASH_ALGORITHM_NAME_MD5 = "MD5";
	public static final String HASH_ALGORITHM_NAME_SHA1 = "SHA-1";
	public static final String HASH_ALGORITHM_NAME_SHA256 = "SHA-256";
	public static final String HASH_ALGORITHM_NAME_SHA512 = "SHA-512";
	public static final String HMAC_ALGORITHM_NAME_MD5 = "HmacMD5";// 128位
	public static final String HMAC_ALGORITHM_NAME_SHA1 = "HmacSHA1";// 126
	public static final String HMAC_ALGORITHM_NAME_SHA256 = "HmacSHA256";// 256
	public static final String HMAC_ALGORITHM_NAME_SHA512 = "HmacSHA512";// 512

	protected static final String DEFAULT_HASH_ALGORITHM_NAME = HASH_ALGORITHM_NAME_MD5;
	protected static final String DEFAULT_HASH_SALT = "A1B2C3D4efg.5679g8e7d6c5b4a_-=_)(8.";
	protected static final Integer DEFAULT_HASH_ITERATIONS = 2;
	protected static final String DEFAULT_HMAC_ALGORITHM_NAME = HMAC_ALGORITHM_NAME_MD5;
	protected static final String DEFAULT_REMEMBERME_SECRETKEY = "A1B2C3D4efg.5679g8e7d6c5b4a_-=_)(8.";
	protected static final Integer DEFAULT_REMEMBERME_MAX_AGE = 86400000 * 7;//// 1天=86400000毫秒(ms);
	protected static final String DEFAULT_JWT_SECRETKEY = "123456789987654321.";
	protected static final Integer DEFAULT_SESSION_TIMEOUT = 3600000;// 1小时=3600000毫秒(ms)
	protected static final Integer DEFAULT_HMAC_DIGEST_TIMEOUT = 3600000;// 10分钟=600000毫秒(ms)
	public static final String DEFAULT_JCAPTCHA_URL = "/jcaptcha.jpg";
	
	public static final String CACHE_NAME_PASSWORD_RETRY = "shiro-passwordRetryCache";
	public static final String CACHE_NAME_KEEP_ONE_USER = "shiro-keepOneUserCache";
	public static final String CACHE_NAME_AUTHENTICATION = "shiro-authenticationCache";
	public static final String CACHE_NAME_AUTHORIZATION = "shiro-authorizationCache";
	
	public static final String ATTRIBUTE_SESSION_CURRENT_USER = "shiro_current_user";
	public static final String ATTRIBUTE_SESSION_CURRENT_USER_ACCOUNT = "shiro_current_user_account";
	public static final String ATTRIBUTE_SESSION_KICKOUT = "shiro_kickout_attribute";
	public static final String ATTRIBUTE_SESSION_FORCE_LOGOUT = "shiro_force_logout_attribute";
	public static final String ATTRIBUTE_REQUEST_AUTH_MESSAGE = "shiro_auth_message";
	
	public static final String MSG_ACCOUNT_EXCEPTION = "账号异常";
	public static final String MSG_ACCOUNT_NOTFOUND = "账号或密码错误";
	public static final String MSG_ACCOUNT_PASSWD_NULL = "账号或密码为空";
	public static final String MSG_ACCOUNT_AUTHC_ERROR = "账号或密码错误";
	//最大次数{total},剩余次数：{remain}
	public static final String MSG_ACCOUNT_AUTHC_RETRY_ERROR = "密码错误,您还可以重试：{remain}次";
	public static final String MSG_HMAC_AUTHC_ERROR = "数字签名无效";
	public static final String MSG_HMAC_DIGEST_TIMEOUT = "数字签名过期";
	public static final String MSG_JWT_TIMEOUT = "令牌过期";
	public static final String MSG_JWT_MALFORMED = "令牌格式错误";
	public static final String MSG_JWT_SIGNATURE = "令牌数字签名错误";
	public static final String MSG_JWT_AUTHC_ERROR = "令牌无效";
	
	

	
	
	
	public static final String PARAM_HMAC_APP_ID = "hmac_app_id";
	public static final String PARAM_HMAC_TIMESTAMP = "hmac_timestamp";
	public static final String PARAM_HMAC_DIGEST = "hmac_digest";
	public static final String PARAM_JWT = "jwt";
	
	// 绝不能混合其他HTTP错误码。例如，使用401响应“登录失败”，使用403响应“权限不够”。这会使客户端无法有效识别HTTP错误码和业务错误，
	// 其原因在于HTTP协议定义的错误码十分偏向底层，而REST API属于“高层”协议，不应该复用底层的错误码。
	// 认证成功
	public static final String REST_CODE_AUTH_SUCCEED = "auth:succeed";
	// 认证成功
	public static final String REST_MESSAGE_AUTH_SUCCEED = "身份验证成功";
	// 认证失败
	public static final String REST_CODE_AUTH_LOGIN_ERROR = "auth:login_error";
	// 认证失败
	public static final String REST_MESSAGE_AUTH_LOGIN_ERROR = "身份验证失败";
	// 未认证
	public static final String REST_CODE_AUTH_UNAUTHORIZED = "auth:unauthorized";
	// 未认证
	public static final String REST_MESSAGE_AUTH_UNAUTHORIZED = "需要身份验证";
	// 未授权
	public static final String REST_CODE_AUTH_FORBIDDEN = "auth:forbidden";
	// 未授权
	public static final String REST_MESSAGE_AUTH_FORBIDDEN = "权限不足";
	// 无用户
	public static final String REST_CODE_AUTH_USER_NOT_FOUND = "auth:user_not_found";
	// 密码错误
	public static final String REST_CODE_AUTH_NO_PERMISSION = "auth:bad_password";
	// 未知错误
	public static final String REST_CODE_INTERNAL_UNKNOWN_ERROR = "internal:unknown_error";
	
	
	
	

	private String loginUrl;// 登陆地址
	private String loginSuccessUrl;// 登陆成功地址
	private String unauthorizedUrl;// 无访问权限地址
	private String kickoutUrl;// 被踢出地址
	private String forceLogoutUrl;// 强制退出地址

	private boolean keepOneEnabled = Boolean.FALSE;// 是否一个账号只允许一个用户登陆
	private boolean jcaptchaEnable = Boolean.FALSE;// 是否启用验证码
	private boolean forceLogoutEnable = Boolean.FALSE;// 是否启用验证码

	private Integer passwdMaxRetries = 0;// 登陆最大重试次数
	private Integer sessionTimeout = DEFAULT_SESSION_TIMEOUT;// session超时时间
	private Integer remembermeMaxAge = DEFAULT_REMEMBERME_MAX_AGE;// rememberMe时间
	private String remembermeSecretKey = DEFAULT_REMEMBERME_SECRETKEY;// rememberMe秘钥

	private String passwdAlg = DEFAULT_HASH_ALGORITHM_NAME;// 密码算法
	private String passwdSalt = DEFAULT_HASH_SALT;// 密码HASH盐
	private Integer passwdIterations = DEFAULT_HASH_ITERATIONS;// 密码HASH次数
	private String hmacAlg = DEFAULT_HMAC_ALGORITHM_NAME;// HMAC算法
	private String hmacSecretKey;// HMAC秘钥
	private Integer hmacDigestTimeout = DEFAULT_HMAC_DIGEST_TIMEOUT;// HMAC签名有效时间
	private String jwtSecretKey;// JWT秘钥

	private boolean ehcacheEnabled = Boolean.FALSE;// 启用ehcache缓存
	private String ehcacheConfigFile;// ehcache配置文件
	private boolean redisEnabled = Boolean.FALSE;// 启用redis缓存
	private boolean authCacheEnabled = Boolean.FALSE;// 启用realm缓存
	private boolean hmacEnabled = Boolean.FALSE;// 启用realm缓存
	private boolean jwtEnabled = Boolean.FALSE;// 启用realm缓存

	public static List<String> DEFAULT_IGNORED = Arrays.asList(
											"/**/favicon.ico"
											,"/css/**"
											,"/js/**"
											,"/images/**"
											,"/webjars/**"
											,"/jcaptcha*");
	private List<String> filteRules = new LinkedList<String>();// 过滤规则

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

	public String getEhcacheConfigFile() {
		return ehcacheConfigFile;
	}

	public void setEhcacheConfigFile(String ehcacheConfigFile) {
		this.ehcacheConfigFile = ehcacheConfigFile;
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

	public boolean isEhcacheEnabled() {
		return ehcacheEnabled;
	}

	public void setEhcacheEnabled(boolean ehcacheEnabled) {
		this.ehcacheEnabled = ehcacheEnabled;
	}

	public boolean isRedisEnabled() {
		return redisEnabled;
	}

	public void setRedisEnabled(boolean redisEnabled) {
		this.redisEnabled = redisEnabled;
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

	public Integer getHmacDigestTimeout() {
		return hmacDigestTimeout;
	}
	public void setHmacDigestTimeout(Integer hmacDigestTimeout) {
		this.hmacDigestTimeout = hmacDigestTimeout;
	}
}