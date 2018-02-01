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

import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.authc.StatelessLocals;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.filter.FilterManager;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.StatelessLogined;
import org.jsets.shiro.realm.RealmManager;
import org.jsets.shiro.service.ShiroCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.collect.Lists;
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
	
	private static ShiroProperties shiroProperties;
	private static ShiroCryptoService cryptoService;
	private static DefaultWebSessionManager sessionManager;
	private static CacheDelegator shiroCacheDelegator;
	private static RealmManager realmManager;
	private static ShiroFilterFactoryBean shiroFilterFactoryBean;
	private static FilterManager filterManager;
	

	/**
	 * 生成密码
	 * @param plaintext 明文
	 */
	public static String password(String plaintext) {
		return cryptoService.password(plaintext);
	}
	/**
	 * 签发JWT
	 * @param subject 用户名称
	 * @param issuer 签发人
	 * @param period 有效时间
	 * @param roles 访问主张-角色
	 * @param permissions 访问主张-资源
	 * @param algorithm 算法
	 * @return JSON WEB TOKEN
	 */
	public static String issueJwt(String subject,String issuer,Long period,String roles,String permissions,SignatureAlgorithm algorithm) {
		return CryptoUtil.issueJwt(shiroProperties.getJwtSecretKey(),subject,issuer,period,roles,permissions,algorithm);
	}
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public static StatelessLogined parseJwt(String jwt) {
		return cryptoService.parseJwt(jwt);
	}
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public static String hmacDigest(String plaintext,String appKey) {
		return cryptoService.hmacDigest(plaintext,appKey);
	}
	/**
	 * 获取当前登陆的用户
	 */
	public static Account getUser() {
		Session currentSession = SecurityUtils.getSubject().getSession(false);
		if(null != currentSession){
			return (Account) currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER);
		} else{
			return StatelessLocals.getAccount();
		}
	}
	/**
	 * 当前用户是否拥有角色
	 * @param roleName 角色名称
	 */
	public static boolean hasRole(String roleName) {
		return SecurityUtils.getSubject().hasRole(roleName);
	}
	/**
	 * 当前用户是否拥有权限
	 * @param permName 权限名称
	 */
	public static boolean hasPerms(String permName) {
		try{
			SecurityUtils.getSubject().checkPermission("testPermission");
			return true;
		}catch(AuthorizationException e){
			//不处理	
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
		if(isRunAs()){
			SecurityUtils.getSubject().releaseRunAs();  
		}
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
		return sessionManager.getSessionDAO().getActiveSessions().size();
	}
	/**
	 * 获取活跃的SESSION
	 */
	public static List<Session> getActiveSessions() {
		return Collections.unmodifiableList(Lists.newArrayList(sessionManager.getSessionDAO().getActiveSessions()));
	}
	/**
	 * 强制退出
	 * @param sessionId 退出的sessionId
	 */
	public static boolean forceLogout(String sessionId) {
		try {
			Session session = sessionManager.getSession(new DefaultSessionKey(sessionId));
			if (session != null) {
				session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_FORCE_LOGOUT, Boolean.TRUE);
			}
			return Boolean.TRUE;
		} catch (UnknownSessionException e) { 
			LOGGER.warn(e.getMessage());
		}
		return Boolean.FALSE;
	}
	
	/**
	 * 删除account的认证、授权缓存
	 * <br>如果启用了auth缓存，当用户的认证信息和角色信息发生了改变，一定要执行此操作。
	 * <br>否则只能等到用户再次登录这些变更才能生效。
	 */
	public static void clearAuthCache(String account) {
		for(Realm cachedRealm:realmManager.getCachedRealms()){
			shiroCacheDelegator.clearAuthCache(account,cachedRealm.getName());
		}
	}
	
	/**
	 * 刷新动态过滤规则
	 * <br>如果角色-资源对应关系发生编号，可以通过此方法进行同步刷新，从而达到URL动态过滤的效果。
	 */
	public static void reloadFilterRules() {
		filterManager.reloadFilterChain(shiroFilterFactoryBean);
	}

	
	public static ShiroProperties getShiroProperties() {
		return shiroProperties;
	}
	public static ShiroCryptoService getCryptoService() {
		return cryptoService;
	}
	public static DefaultWebSessionManager getSessionManager() {
		return sessionManager;
	}
	public static CacheDelegator getShiroCacheDelegator() {
		return shiroCacheDelegator;
	}
	public static RealmManager getRealmManager() {
		return realmManager;
	}
	public static ShiroFilterFactoryBean getShiroFilterFactoryBean() {
		return shiroFilterFactoryBean;
	}
	public static FilterManager getFilterManager() {
		return filterManager;
	}
	
	public static void setShiroProperties(ShiroProperties shiroProperties) {
		ShiroUtils.shiroProperties = shiroProperties;
	}
	public static void setCryptoService(ShiroCryptoService cryptoService) {
		ShiroUtils.cryptoService = cryptoService;
	}
	public static void setSessionManager(DefaultWebSessionManager sessionManager) {
		ShiroUtils.sessionManager = sessionManager;
	}
	public static void setShiroCacheDelegator(CacheDelegator shiroCacheDelegator) {
		ShiroUtils.shiroCacheDelegator = shiroCacheDelegator;
	}
	public static void setRealmManager(RealmManager realmManager) {
		ShiroUtils.realmManager = realmManager;
	}
	public static void setShiroFilterFactoryBean(ShiroFilterFactoryBean shiroFilterFactoryBean) {
		ShiroUtils.shiroFilterFactoryBean = shiroFilterFactoryBean;
	}
	public static void setFilterManager(FilterManager filterManager) {
		ShiroUtils.filterManager = filterManager;
	}
}