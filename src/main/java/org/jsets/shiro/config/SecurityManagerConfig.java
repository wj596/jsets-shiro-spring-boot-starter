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

import java.util.List;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.jsets.shiro.handler.PasswdRetryLimitHandler;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;

import com.google.common.collect.Lists;
/**
 * 应用端配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class SecurityManagerConfig {

	private ShiroAccountProvider accountProvider;
	private ShiroStatelessAccountProvider statelessAccountProvider;
	private PasswdRetryLimitHandler passwdRetryLimitHandler;
	private SimpleCookie rememberMeCookie;
	private SessionDAO sessionDAO;
	private CacheManager cacheManager;
	private final List<SessionListener> sessionListeners = Lists.newLinkedList();
	private final List<Realm> realms = Lists.newLinkedList();
	
	
	
	/**
	 * 设置账号信息提供者
	 * @param accountProviderImpl  see org.jsets.shiro.service.ShiroAccountProvider
	 */
	public void setAccountProvider(ShiroAccountProvider accountProviderImpl) {
		this.accountProvider = accountProviderImpl;
	}
	/**
	 * 设置密码错误次数超限处理器
	 * @param passwdRetryLimitHandlerImpl  see org.jsets.shiro.service.PasswdRetryLimitHandler
	 */
	public void setPasswdRetryLimitHandler(PasswdRetryLimitHandler passwdRetryLimitHandlerImpl) {
		this.passwdRetryLimitHandler = passwdRetryLimitHandlerImpl;
	}
	/**
	 * 设置无状态鉴权(HMAC、JWT)账号信息提供者
	 * <br>如果不设置此项无状态鉴权默认使用accountProviderImpl作为账号信息提供者
	 * 
	 * @param statelessAccountProviderImpl  see org.jsets.shiro.service.ShiroStatelessAccountProvider
	 */
	public void setStatelessAccountProvider(ShiroStatelessAccountProvider statelessAccountProviderImpl) {
		this.statelessAccountProvider = statelessAccountProviderImpl;
	}
	/**
	 * 设置RememberMe  Cookie的模板
	 * <br>如需要定制RememberMe Cookie的name、domain、httpOnly可设置此项
	 * 
	 * @param rememberMeCookie  see org.apache.shiro.web.servlet.SimpleCookie
	 */
	public void setRememberMeCookie(SimpleCookie rememberMeCookie) {
		this.rememberMeCookie = rememberMeCookie;
	}
	/**
	 * 设置SessionDAO
	 * <br>如果组件提供的session缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制session持久化
	 * 
	 * @param sessionDAO  see org.apache.shiro.session.mgt.eis.SessionDAO
	 */
	public void setSessionDAO(SessionDAO sessionDAO) {
		this.sessionDAO = sessionDAO;
	}
	/**
	 * 设置SessionDAO
	 * <br>如果组件提供的缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制缓存实现
	 * 
	 * @param cacheManager  see org.apache.shiro.cache.CacheManager
	 */
	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}
	/**
	 * 添加鉴权控制域
	 * <br>组件中提供三个控制域
	 * <br>AccountPasswdRealm:有状态用户名,密码鉴权控制域
	 * <br>HmacRealm:无状态hmac签名鉴权控制域
	 * <br>JwtRealm:无状态jwt令牌鉴权控制域
	 * <br>如果无法满足需求，可设置此项添加鉴权控制域
	 * @param cacheManager  see org.apache.shiro.cache.CacheManager
	 */
	public void addRealm(Realm realm) {
		this.realms.add(realm);
	}
	
	protected ShiroAccountProvider getAccountProvider() {
		return accountProvider;
	}
	protected ShiroStatelessAccountProvider getStatelessAccountProvider() {
		return statelessAccountProvider;
	}
	protected PasswdRetryLimitHandler getPasswdRetryLimitHandler() {
		return passwdRetryLimitHandler;
	}
	protected SimpleCookie getRememberMeCookie() {
		return rememberMeCookie;
	}
	protected SessionDAO getSessionDAO() {
		return sessionDAO;
	}
	protected CacheManager getCacheManager() {
		return cacheManager;
	}
	protected void addSessionListener(SessionListener sessionListener) {
		this.sessionListeners.add(sessionListener);
	}
	protected List<SessionListener> getSessionListeners() {
		return sessionListeners;
	}
	protected List<Realm> getRealms() {
		return this.realms;
	}
}