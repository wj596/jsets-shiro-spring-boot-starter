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
package org.jsets.shiro.api;

import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.servlet.Cookie;
import org.jsets.shiro.api.PasswordProvider;
import org.jsets.shiro.api.ShiroAccountProvider;
import org.jsets.shiro.api.ShiroFilteRulesProvider;
import org.jsets.shiro.api.ShiroStatelessAccountProvider;
import org.jsets.shiro.listener.AuthListener;
import org.jsets.shiro.listener.AuthListenerManager;
import org.jsets.shiro.listener.PasswdRetryLimitListener;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * shiro自动配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class ShiroCustomizer {

	private PasswordProvider passwordProvider;
	private ShiroAccountProvider shiroAccountProvider;
	private ShiroStatelessAccountProvider shiroStatelessAccountProvider;
	private ShiroFilteRulesProvider shiroFilteRulesProvider;
	private PasswdRetryLimitListener passwdRetryLimitListener;
	private CaptchaProvider captchaProvider;
	private SessionDAO sessionDAO;
	private List<SessionListener> sessionListeners = Lists.newLinkedList();
	private Cookie rememberMeCookie;
	private CacheManager cacheManager;
	private Map<String,Realm> realms = Maps.newLinkedHashMap();
	private Map<String,Filter> filters = Maps.newLinkedHashMap();
	private AuthListenerManager authListenerManager = new AuthListenerManager();

	private ShiroCustomizer self() {
		return this;
	}

	/**
	 * 验证码提供者接口
	 * <br>
	 * 应用系统实现这个接口以便使用自己的验证码
	 * 
	 * @param accountProviderImpl  
	 * see org.jsets.shiro.api.CaptchaProvider
	 */
	public ShiroCustomizer setCaptchaProvider(CaptchaProvider captchaProvider) {
		this.captchaProvider = captchaProvider;
		return self();
	}
	
	
	/**
	 * 密码提供者接口
	 * <br>
	 * 应用系统实现这个接口以便使用自己的加密算法
	 * 
	 * @param accountProviderImpl  
	 * see org.jsets.shiro.api.ShiroAccountProvider
	 */
	public ShiroCustomizer setPasswordProvider(PasswordProvider passwordProvider) {
		this.passwordProvider = passwordProvider;
		return self();
	}
	
	
	/**
	 * 设置账号信息提供者
	 * 
	 * @param accountProviderImpl  
	 * see org.jsets.shiro.api.ShiroAccountProvider
	 */
	public ShiroCustomizer setShiroAccountProvider(ShiroAccountProvider shiroAccountProvider) {
		this.shiroAccountProvider = shiroAccountProvider;
		return self();
	}

	
	/**
	 * 设置无状态鉴权(HMAC、JWT)账号信息提供者
	 * <br>如果不设置此项无状态鉴权默认使用accountProviderImpl作为账号信息提供者
	 * 
	 * @param statelessAccountProviderImpl  
	 * see org.jsets.shiro.api.ShiroStatelessAccountProvider
	 */
	public ShiroCustomizer setShiroStatelessAccountProvider(ShiroStatelessAccountProvider shiroStatelessAccountProvider) {
		this.shiroStatelessAccountProvider = shiroStatelessAccountProvider;
		return self();
	}
	/**
	 * 
	 *  设置过滤规则提供者，实现动态URL鉴权过滤
	 *  
	 *  @param shiroFilteRulesProvider 
	 *  @see org.jsets.shiro.api.ShiroFilteRulesProvider
	 *  
	 */
	public ShiroCustomizer setShiroFilteRulesProvider(ShiroFilteRulesProvider shiroFilteRulesProvider) {
		this.shiroFilteRulesProvider = shiroFilteRulesProvider;
		return self();
	}
	
	
	/**
	 * 设置密码错误次数超限处理器
	 * 
	 * @param passwdRetryLimitHandlerImpl  
	 * see org.jsets.shiro.service.PasswdRetryLimitHandler
	 */
	public ShiroCustomizer setPasswdRetryLimitListener(PasswdRetryLimitListener passwdRetryLimitListener) {
		this.passwdRetryLimitListener = passwdRetryLimitListener;
		return self();
	}
	
	
	/**
	 * 设置SessionDAO
	 * <br>
	 * 如果组件提供的session缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制session持久化
	 * 
	 * @param sessionDAO  see org.apache.shiro.session.mgt.eis.SessionDAO
	 */
	public ShiroCustomizer setSessionDAO(SessionDAO sessionDAO) {
		this.sessionDAO = sessionDAO;
		return self();
	}

	
	/**
	 * 添加session监听器
	 * <br>
	 * 
	 * @param SessionListener  see org.apache.shiro.session.SessionListener
	 */
	public ShiroCustomizer addSessionListener(SessionListener sessionListener) {
		this.sessionListeners.add(sessionListener);
		return self();
	}
	
	public ShiroCustomizer addSessionListeners(SessionListener... sessionListeners) {
		for(SessionListener sl:sessionListeners)
			this.sessionListeners.add(sl);
		return self();
	}
	
	public ShiroCustomizer addAuthListener(AuthListener listener) {
		this.authListenerManager.add(listener);
		return self();
	}
	
	public ShiroCustomizer addAuthListeners(AuthListener... listeners) {
		for(AuthListener sl:listeners)
			this.authListenerManager.add(sl);
		return self();
	}

	/**
	 * 设置RememberMe  Cookie的模板
	 * <br>如需要定制RememberMe Cookie的name、domain、httpOnly可设置此项
	 * 
	 * @param rememberMeCookie  see org.apache.shiro.web.servlet.SimpleCookie
	 */
	public ShiroCustomizer setRememberMeCookie(Cookie rememberMeCookie) {
		this.rememberMeCookie = rememberMeCookie;
		return self();
	}
	
	/**
	 * 设置CacheManager
	 * <br>如果组件提供的缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制缓存实现
	 * 
	 * @param cacheManager  see org.apache.shiro.cache.CacheManager
	 */
	public ShiroCustomizer setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
		return self();
	}
	
	/**
	 * 添加鉴权控制域
	 * <br>组件中提供三个控制域
	 * <br>PasswdRealm:有状态用户名,密码鉴权控制域
	 * <br>HmacRealm:无状态hmac签名鉴权控制域
	 * <br>JwtRealm:无状态jwt令牌鉴权控制域
	 * <br>如果无法满足需求，可设置此项添加鉴权控制域
	 * @param cacheManager  see org.apache.shiro.cache.CacheManager
	 */
	public ShiroCustomizer addRealm(String realName,Realm realm) {
		this.realms.put(realName, realm);
		return self();
	}
	
	/**
	 * 
	 * 
	 *  添加鉴权过滤
	 * <br>组件中提供的过滤器：
	 * <br>authc:基于表单的登陆过滤器
	 * <br>roles:基于角色的验证过滤器
	 * <br>perms:基于权限的验证过滤器
	 * <br>user:断言seesion中存在用户的过滤器
	 * <br>keepOne:账号唯一用户登陆过滤器
	 * <br>forceLogout:强制用户下线过滤器
	 * <br>hmac:hmac数字签名认证过滤器
	 * <br>hmacRoles:hmac数字签名角色验证过滤器
	 * <br>hmacPerms:hmac数字签名权限验证过滤器
	 * <br>jwt:jwt令牌认证过滤器
	 * <br>jwtRoles:jwt令牌角色验证过滤器
	 * <br>jwtPerms:jwt令牌权限验证过滤器
	 * <br>如果无法满足需求，可设置此项覆盖或者添加过滤器
	 * 
	 * 
	 * 
	 * @param filterName 过滤器名称
	 * @param filter 过滤器
	 */
	public ShiroCustomizer addFilter(String filterName,Filter filter) {
		this.filters.put(filterName, filter);
		return self();
	}

	
	public CaptchaProvider getCaptchaProvider() {
		return captchaProvider;
	}

	public PasswordProvider getPasswordProvider() {
		return passwordProvider;
	}

	public ShiroAccountProvider getShiroAccountProvider() {
		return shiroAccountProvider;
	}

	public ShiroStatelessAccountProvider getShiroStatelessAccountProvider() {
		return shiroStatelessAccountProvider;
	}

	public ShiroFilteRulesProvider getShiroFilteRulesProvider() {
		return shiroFilteRulesProvider;
	}

	public PasswdRetryLimitListener getPasswdRetryLimitListener() {
		return passwdRetryLimitListener;
	}

	public SessionDAO getSessionDAO() {
		return sessionDAO;
	}

	public List<SessionListener> getSessionListeners() {
		return sessionListeners;
	}

	public Cookie getRememberMeCookie() {
		return rememberMeCookie;
	}

	public CacheManager getCacheManager() {
		return cacheManager;
	}

	public Map<String,Realm> getRealms() {
		return realms;
	}

	public Map<String,Filter> getFilters() {
		return filters;
	}
	
	public AuthListenerManager getAuthListenerManager() {
		return this.authListenerManager;
	}
}