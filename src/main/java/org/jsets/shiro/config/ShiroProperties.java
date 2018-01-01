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

	public static final String DEFAULT_JCAPTCHA_URL = "/jcaptcha.jpg";
	// 默认SESSION超时时间：1小时=3600000毫秒(ms)
	protected static final Integer DEFAULT_SESSION_TIMEOUT = 3600000;
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
	protected static final String DEFAULT_REMEMBERME_SECRETKEY = "A1B2C3D4efg.5679g8e7d6c5b4a_-=_)(8.";
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
	// ATTRIBUTE名称
	public static final String ATTRIBUTE_SESSION_CURRENT_USER = "shiro_current_user";
	public static final String ATTRIBUTE_SESSION_CURRENT_USER_ACCOUNT = "shiro_current_user_account";
	public static final String ATTRIBUTE_SESSION_KICKOUT = "shiro_kickout_attribute";
	public static final String ATTRIBUTE_SESSION_FORCE_LOGOUT = "shiro_force_logout_attribute";
	public static final String ATTRIBUTE_REQUEST_AUTH_MESSAGE = "shiro_auth_message";
	//  PARAM名称
	public static final String PARAM_JCAPTCHA = "jcaptcha";
	public static final String PARAM_HMAC_APP_ID = "hmac_app_id";
	public static final String PARAM_HMAC_TIMESTAMP = "hmac_timestamp";
	public static final String PARAM_HMAC_DIGEST = "hmac_digest";
	public static final String PARAM_JWT = "jwt";
	
	
	
	public static final List<String> DEFAULT_IGNORED = Arrays.asList(
													"/**/favicon.ico"
													,"/css/**"
													,"/js/**"
													,"/images/**"
													,"/webjars/**"
													,"/jcaptcha.jpg");
	
	private boolean jcaptchaEnable = Boolean.FALSE; // 是否启用验证码
	private boolean keepOneEnabled = Boolean.FALSE; // 是否启用账号唯一用户登陆
	private boolean forceLogoutEnable = Boolean.FALSE; // 是否启用强制用户下线
	private boolean ehcacheEnabled = Boolean.FALSE; // 是否启用ehcache缓存
	private boolean redisEnabled = Boolean.FALSE; // 是否启用redis缓存
	private boolean authCacheEnabled = Boolean.FALSE;// 是否启用认证授权缓存
	private boolean hmacEnabled = Boolean.FALSE; // 是否启用HMAC鉴权
	private boolean jwtEnabled = Boolean.FALSE; // 是否启用JWT鉴权
	
	private String loginUrl;// 登陆地址
	private String loginSuccessUrl;// 登陆成功地址
	private String unauthorizedUrl;// 无访问权限地址
	private String kickoutUrl;// 被踢出地址
	private String forceLogoutUrl;// 强制退出地址

	private Integer passwdMaxRetries = 0;// 登陆最大重试次数
	private Integer sessionTimeout = DEFAULT_SESSION_TIMEOUT;// session超时时间
	private Integer remembermeMaxAge = DEFAULT_REMEMBERME_MAX_AGE;// rememberMe时间
	private String remembermeSecretKey = DEFAULT_REMEMBERME_SECRETKEY;// rememberMe秘钥
	private String passwdAlg = DEFAULT_HASH_ALGORITHM_NAME;// 密码算法
	private String passwdSalt = DEFAULT_HASH_SALT;// 密码HASH盐
	private Integer passwdIterations = DEFAULT_HASH_ITERATIONS;// 密码HASH次数
	
	private String ehcacheConfigFile;// ehcache配置文件
	
	private String hmacAlg = DEFAULT_HMAC_ALGORITHM_NAME;// HMAC算法
	private String hmacSecretKey;// HMAC秘钥
	private Integer hmacPeriod = DEFAULT_HMAC_PERIOD;// HMAC签名有效时间
	private String jwtSecretKey;// JWT秘钥
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
	public Integer getHmacPeriod() {
		return hmacPeriod;
	}
	public void setHmacPeriod(Integer hmacPeriod) {
		this.hmacPeriod = hmacPeriod;
	}
}