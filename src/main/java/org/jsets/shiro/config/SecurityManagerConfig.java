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
	
	public ShiroAccountProvider getAccountProvider() {
		return accountProvider;
	}
	public void setAccountProvider(ShiroAccountProvider accountProvider) {
		this.accountProvider = accountProvider;
	}
	public ShiroStatelessAccountProvider getStatelessAccountProvider() {
		return statelessAccountProvider;
	}
	public void setStatelessAccountProvider(ShiroStatelessAccountProvider statelessAccountProvider) {
		this.statelessAccountProvider = statelessAccountProvider;
	}
	public PasswdRetryLimitHandler getPasswdRetryLimitHandler() {
		return passwdRetryLimitHandler;
	}
	public void setPasswdRetryLimitHandler(PasswdRetryLimitHandler passwdRetryLimitHandler) {
		this.passwdRetryLimitHandler = passwdRetryLimitHandler;
	}
	public SimpleCookie getRememberMeCookie() {
		return rememberMeCookie;
	}
	public void setRememberMeCookie(SimpleCookie rememberMeCookie) {
		this.rememberMeCookie = rememberMeCookie;
	}
	public SessionDAO getSessionDAO() {
		return sessionDAO;
	}
	public void setSessionDAO(SessionDAO sessionDAO) {
		this.sessionDAO = sessionDAO;
	}
	public CacheManager getCacheManager() {
		return cacheManager;
	}
	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}
	public void addSessionListener(SessionListener sessionListener) {
		this.sessionListeners.add(sessionListener);
	}
	public List<SessionListener> getSessionListeners() {
		return sessionListeners;
	}
	public void addRealm(Realm realm) {
		this.realms.add(realm);
	}
	public List<Realm> getRealms() {
		return this.realms;
	}
}