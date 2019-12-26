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
package org.jsets.shiro.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.realm.CachingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.jsets.shiro.config.ShiroConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.StatelessAccount;
import com.google.common.collect.Lists;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * SHIRO工具
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class ShiroUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(ShiroUtils.class);

	private static final ThreadLocal<Account> STATELESSES = new ThreadLocal<Account>();

	/**
	 * 生成密码
	 * 
	 * @param plaintext
	 *            明文
	 */
	public static String password(String plainPassord) {
		return shiroConfig().getPasswordProvider().encrypt(plainPassord);
	}

	/**
	 * 生成HMAC摘要
	 *
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public static String hmacDigest(String plaintext) {
		return hmacDigest(plaintext,properties().getHmacSecretKey());
	}

	/**
	 * 生成HMAC摘要
	 *
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public static String hmacDigest(String plaintext, String secretKey) {
		return hmacDigest(properties().getHmacAlg(), plaintext, properties().getHmacSecretKey());
	}

	/**
	 * 生成HMAC摘要
	 *
	 * @param algorithm 算法
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public static String hmacDigest(String algorithm, String plaintext, String secretKey) {
		try {
			Mac mac = Mac.getInstance(algorithm);
			byte[] secretByte = secretKey.getBytes();
			byte[] dataBytes = plaintext.getBytes();
			SecretKey secret = new SecretKeySpec(secretByte, algorithm);
			mac.init(secret);
			byte[] doFinal = mac.doFinal(dataBytes);
			return CommonUtils.byte2HexStr(doFinal);
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	/**
	 * 验签JWT
	 *
	 * @param jwt json web token
	 */
	public static StatelessAccount parseJwt(String jwt, String secretKey) {
		Claims claims = Jwts.parser()
							.setSigningKey(DatatypeConverter.parseBase64Binary(secretKey))
							.parseClaimsJws(jwt)
							.getBody();
		StatelessAccount statelessAccount = new StatelessAccount();
		statelessAccount.setTokenId(claims.getId());// 令牌ID
		statelessAccount.setAppId(claims.getSubject());// 客户标识
		statelessAccount.setIssuer(claims.getIssuer());// 签发者
		statelessAccount.setIssuedAt(claims.getIssuedAt());// 签发时间
		statelessAccount.setAudience(claims.getAudience());// 接收方
		statelessAccount.setRoles(claims.get("roles", String.class));// 访问主张-角色
		statelessAccount.setPerms(claims.get("perms", String.class));// 访问主张-权限
		return statelessAccount;
	}

	/**
	 * 签发JWT
	 * 
	 * @param subject
	 *            用户名称
	 * @param issuer
	 *            签发人
	 * @param period
	 *            有效时间
	 * @param roles
	 *            访问主张-角色
	 * @param permissions
	 *            访问主张-资源
	 * @param algorithm
	 *            算法
	 * @return JSON WEB TOKEN
	 */
	public static String issueJwt(String subject, String issuer, Long period, String roles, String permissions,
			SignatureAlgorithm algorithm) {
		// 当前时间戳(精确到毫秒)
		long currentTimeMillis = System.currentTimeMillis();
		// 秘钥
		byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(properties().getJwtSecretKey());
		JwtBuilder jwt = Jwts.builder();
		jwt.setId(UUID.randomUUID().toString());
		// 用户名
		jwt.setSubject(subject);
		// 签发者
		if (null != issuer && !"".equals(issuer))
			jwt.setIssuer(issuer);
		// 签发时间
		jwt.setIssuedAt(new Date(currentTimeMillis));
		// 有效时间
		if (null != period) {
			Date expiration = new Date(currentTimeMillis + period);
			jwt.setExpiration(expiration);
		}
		// 访问主张-角色
		if (null != roles && !"".equals(roles))
			jwt.claim("roles", roles);
		// 访问主张-权限
		if (null != permissions && !"".equals(permissions))
			jwt.claim("perms", permissions);
		jwt.compressWith(CompressionCodecs.DEFLATE);
		jwt.signWith(algorithm, secretKeyBytes);
		return jwt.compact();
	}

	/**
	 * 获取当前登陆的用户
	 */
	public static <T extends Account> T getUser() {
		Session currentSession = SecurityUtils.getSubject().getSession(false);
		if (null != currentSession) {
			return (T)currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER);
		} else {
			return (T)getStatelessAccount();
		}
	}

	/**
	 * 获取当前登陆的用户
	 */
	public static String getPrincipal() {
		return (String) SecurityUtils.getSubject().getPrincipal();
	}

	/**
	 * 判断当前是否登陆
	 */
	public static boolean isAuthenticated() {
		return SecurityUtils.getSubject().isAuthenticated();
	}

	/**
	 * 当前用户是否拥有角色
	 * 
	 * @param roleName
	 *            角色名称
	 */
	public static boolean hasRole(String roleName) {
		return SecurityUtils.getSubject().hasRole(roleName);
	}

	/**
	 * 当前用户是否拥有权限
	 * 
	 * @param permName
	 *            权限名称
	 */
	public static boolean hasPerms(String permission) {
		try {
			SecurityUtils.getSubject().checkPermission(permission);
			return true;
		} catch (AuthorizationException e) {
			// 不处理
		}
		return false;
	}

	/**
	 * 当前用户切换成switchUserId的身份
	 */
	public static void runAs(String switchUserId) {
		SecurityUtils.getSubject().runAs(new SimplePrincipalCollection(switchUserId, ""));
	}

	/**
	 * 当前用户是否以切换的身份运行
	 */
	public static boolean isRunAs() {
		return SecurityUtils.getSubject().isRunAs();
	}

	/**
	 * 当前用户是否以切换的身份运行，还原到上一身份
	 */
	public static void releaseRunAs() {
		if (isRunAs())
			SecurityUtils.getSubject().releaseRunAs();
	}

	/**
	 * 设置认证信息
	 */
	public static void setAuthMessage(HttpServletRequest request, String message) {
		request.setAttribute(ShiroProperties.ATTRIBUTE_REQUEST_AUTH_MESSAGE, message);
	}

	/**
	 * 获取活跃的SESSION数量
	 */
	public static int getActiveSessionCount() {
		return shiroConfig().getSessionManager().getSessionDAO().getActiveSessions().size();
	}

	/**
	 * 获取活跃的SESSION
	 */
	public static List<Session> getActiveSessions() {
		return Collections.unmodifiableList(Lists.newArrayList(
					shiroConfig().getSessionManager().getSessionDAO().getActiveSessions()));
	}

	/**
	 * 强制退出
	 * 
	 * @param sessionId
	 *            退出的sessionId
	 */
	public static boolean forceLogout(String sessionId) {
		try {
			Session session = shiroConfig().getSessionManager().getSession(new DefaultSessionKey(sessionId));
			if (session != null) {
				session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_FORCE_LOGOUT, Boolean.TRUE);
			}
			return Boolean.TRUE;
		} catch (UnknownSessionException e) {
			LOGGER.warn(e.getMessage(), e);
		}
		return Boolean.FALSE;
	}

	/**
	 * 获取当前Ssssion
	 */
	public static Session getSession() {
		return SecurityUtils.getSubject().getSession();
	}

	/**
	 * 删除account的认证、授权缓存 <br>
	 * 如果启用了auth缓存，当用户的认证信息和角色信息发生了改变，一定要执行此操作。 <br>
	 * 否则只能等到用户再次登录这些变更才能生效。
	 */
	public static void clearAuthCache(String account) {

		shiroConfig().getRealms().stream()
				.filter(r -> (r instanceof CachingRealm) && ((CachingRealm) r).isCachingEnabled())
				.forEach(r -> shiroConfig().getCacheDelegator().clearAuthCache(account, r.getName()));
	}

	/**
	 * 刷新动态过滤规则 <br>
	 * 如果角色-资源对应关系发生变更，可以通过此方法进行同步刷新，从而达到URL动态过滤的效果。
	 */
	public static void reloadFilterRules() {
		shiroConfig().reloadFilterRules(getFilterFactoryBean());
	}

	public static Account getStatelessAccount() {
		return STATELESSES.get();
	}

	public static void setStatelessAccount(Account account) {
		STATELESSES.set(account);
	}

	public static void removeStatelessAccount() {
		STATELESSES.remove();
	}
	
	public static ShiroProperties properties() {
		return SpringContextUtils.getBean(ShiroProperties.class);
	}
	
	private static ShiroConfig shiroConfig() {
		return SpringContextUtils.getBean(ShiroConfig.class);
	}
	
	private static ShiroFilterFactoryBean getFilterFactoryBean() {
		return SpringContextUtils.getBean(ShiroFilterFactoryBean.class);
	}
}