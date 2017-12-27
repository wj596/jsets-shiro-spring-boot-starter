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