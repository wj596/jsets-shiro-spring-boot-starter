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

import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.authc.JsetsModularRealmAuthenticator;
import org.jsets.shiro.authc.JsetsPasswdMatcher;
import org.jsets.shiro.authc.JsetsSubjectFactory;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.cache.MapCacheManager;
import org.jsets.shiro.cache.RedisCacheManager;
import org.jsets.shiro.filter.FilterManager;
import org.jsets.shiro.handler.DefaultSessionListener;
import org.jsets.shiro.realm.RealmManager;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.util.Commons;
import org.jsets.shiro.util.ShiroUtils;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.session.SessionListener;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
/**
 * SHIRO构造器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsShiroManager {

	private final ShiroProperties properties;
	private final SecurityManagerConfig managerConfig;
	private final FilterChainConfig filterConfig;
	private DefaultWebSessionManager sessionManager;
	private CookieRememberMeManager rememberMeManager;
	private CacheManager cacheManager;
	private CacheDelegator cacheDelegator;
	private JsetsPasswdMatcher passwdMatcher;
	private RealmManager realmManager;
	private FilterManager filterManager;
	private DefaultWebSecurityManager securityManager;
	private ShiroFilterFactoryBean shiroFilterFactoryBean;
	private RedisConnectionFactory redisConnectionFactory;
	private ShiroCryptoService cryptoService;
	private short cacheType = Commons.CACHE_TYPE_MAP;
	private final AtomicBoolean initialized = new AtomicBoolean(Boolean.FALSE);

	protected JsetsShiroManager(ShiroProperties properties, SecurityManagerConfig managerConfig,
			FilterChainConfig filterConfig) {
		this.properties = properties;
		this.managerConfig = managerConfig;
		this.filterConfig = filterConfig;
	}

	private void buildSessionManager() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(this.properties.getSessionTimeout());
		sessionManager.setSessionIdUrlRewritingEnabled(Boolean.FALSE);
		sessionManager.setSessionDAO(this.getSessionDAO());
		sessionManager.setSessionListeners(this.getSessionListeners());
		sessionManager.setSessionValidationInterval(this.properties.getSessionValidationInterval());
		this.sessionManager = sessionManager;
	}

	private SessionDAO getSessionDAO() {
		if (null != this.managerConfig.getSessionDAO()) {
			return this.managerConfig.getSessionDAO();
		} else {
			return new EnterpriseCacheSessionDAO();
		}
	}

	private List<SessionListener> getSessionListeners() {
		List<SessionListener> listeners = Lists.newLinkedList();
		if (!this.managerConfig.getSessionListeners().isEmpty()) {
			listeners.addAll(this.managerConfig.getSessionListeners());
		}
		DefaultSessionListener defSessionListener = new DefaultSessionListener();
		listeners.add(defSessionListener);
		return listeners;
	}

	private void buildRememberMeManager() {
		CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
		rememberMeManager.setCipherKey(CodecSupport.toBytes(this.properties.getRemembermeSecretKey()));
		rememberMeManager.setCookie(this.getRememberMeCookie());
		this.rememberMeManager = rememberMeManager;
	}

	private SimpleCookie getRememberMeCookie() {
		if (null != this.managerConfig.getRememberMeCookie()) {
			return this.managerConfig.getRememberMeCookie();
		} else {
			SimpleCookie simpleCookie = new SimpleCookie();
			simpleCookie.setName(Commons.REMEMBERME_COOKIE_NAME);
			simpleCookie.setHttpOnly(Boolean.TRUE);
			simpleCookie.setMaxAge(this.properties.getRemembermeMaxAge());
			return simpleCookie;
		}
	}

	private void buildCacheManager() {
		if (null != this.managerConfig.getCacheManager()) {
			this.setCacheType(Commons.CACHE_TYPE_OTHER);
			this.cacheManager = this.managerConfig.getCacheManager();
		} else {
			boolean enabledEhcache = this.properties.isEhcacheEnabled();
			boolean enabledRedis = this.properties.isRedisEnabled();
			if (enabledEhcache && enabledRedis) {
				enabledRedis = Boolean.FALSE;
			}
			if (enabledEhcache && !Strings.isNullOrEmpty(this.properties.getEhcacheConfigFile())) {
				EhCacheManager ehCacheManager = new EhCacheManager();
				ehCacheManager.setCacheManagerConfigFile(this.properties.getEhcacheConfigFile());
				this.setCacheType(Commons.CACHE_TYPE_EHCACHE);
				this.cacheManager = ehCacheManager;
			} else if (enabledRedis && null != this.redisConnectionFactory) {
				RedisCacheManager redisCacheManager = new RedisCacheManager();
				GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();
				RedisTemplate<Object, Object> redisTemplate = new RedisTemplate<Object, Object>();
				redisTemplate.setConnectionFactory(this.redisConnectionFactory);
				redisTemplate.setKeySerializer(jsonSerializer);
				redisTemplate.setHashKeySerializer(jsonSerializer);
				redisTemplate.setBeanClassLoader(this.getClass().getClassLoader());
				redisTemplate.afterPropertiesSet();
				redisCacheManager.setRedisTemplate(redisTemplate);
				this.setCacheType(Commons.CACHE_TYPE_REDIS);
				this.cacheManager = redisCacheManager;
			} else {
				this.setCacheType(Commons.CACHE_TYPE_MAP);
				this.cacheManager = new MapCacheManager();
			}
		}
	}

	private void buildCacheDelegator() {
		CacheDelegator cacheDelegator = new CacheDelegator();
		cacheDelegator.setCacheManager(this.cacheManager);
		cacheDelegator.setCacheType(this.cacheType);
		this.cacheDelegator = cacheDelegator;
	}

	private void buildPasswdMatcher() {

		JsetsPasswdMatcher passwdMatcher = new JsetsPasswdMatcher();
		passwdMatcher.setProperties(this.properties);
		passwdMatcher.setCacheDelegator(this.cacheDelegator);
		passwdMatcher.setCryptoService(this.cryptoService);
		passwdMatcher.setMessages(MessageConfig.ins());
		this.passwdMatcher = passwdMatcher;
	}
	
	private void buildRealmManager() {
		RealmManager realmManager = new RealmManager();
		realmManager.setProperties(this.properties);
		realmManager.setJsetsPasswdMatcher(this.passwdMatcher);
		realmManager.setShiroCryptoService(this.cryptoService);
		realmManager.setAccountProvider(this.managerConfig.getAccountProvider());
		realmManager.setCustomRealms(this.managerConfig.getRealms());
		realmManager.setStatelessAccountProvider(this.managerConfig.getStatelessAccountProvider());
		realmManager.setMessages(MessageConfig.ins());
		realmManager.setCacheDelegator(this.cacheDelegator);
		realmManager.initRealms();
		this.realmManager = realmManager;
	}

	private void buildSecurityManager(){
		this.buildSessionManager();
		this.buildRememberMeManager();
		this.buildCacheManager();
		this.buildCacheDelegator();
		this.buildPasswdMatcher();
		this.buildRealmManager();
		
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setSessionManager(this.sessionManager);
		securityManager.setRememberMeManager(this.rememberMeManager);
		securityManager.setAuthenticator(new JsetsModularRealmAuthenticator());
		DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) securityManager.getSubjectDAO();
		DefaultSessionStorageEvaluator storageEvaluator = 
					(DefaultSessionStorageEvaluator)subjectDAO.getSessionStorageEvaluator();
		JsetsSubjectFactory subjectFactory = new JsetsSubjectFactory(storageEvaluator);
		securityManager.setSubjectFactory(subjectFactory);
		securityManager.setCacheManager(this.cacheManager);
		securityManager.setRealms(this.realmManager.getAllRealms());
		SecurityUtils.setSecurityManager(securityManager);
		this.securityManager =  securityManager;
	}
	
	private void buildFilterManager() {	
		FilterManager filterManager = new FilterManager();
		filterManager.setProperties(this.properties);
		filterManager.setSessionManager(this.sessionManager);
		filterManager.setCacheDelegator(this.cacheDelegator);
		filterManager.setAccountProvider(this.managerConfig.getAccountProvider());
		filterManager.setCustomFilters(this.filterConfig.getFilters());
		filterManager.setRulesProvider(this.filterConfig.getShiroFilteRulesProvider());
		filterManager.setMessages(MessageConfig.ins());
		filterManager.initFixations();
		filterManager.initFilters();
		filterManager.initFilterChain();
		this.filterManager = filterManager;
	}
	
	private void buildShiroFilterFactoryBean() {
		
		this.buildFilterManager();
		
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		if(Commons.hasLen(this.filterManager.getLoginUrl()))
			shiroFilterFactoryBean.setLoginUrl(filterManager.getLoginUrl());
		if(Commons.hasLen(this.filterManager.getSuccessUrl()))
			shiroFilterFactoryBean.setSuccessUrl(filterManager.getSuccessUrl());
		if(Commons.hasLen(this.filterManager.getUnauthorizedUrl()))
			shiroFilterFactoryBean.setUnauthorizedUrl(filterManager.getUnauthorizedUrl());
		shiroFilterFactoryBean.setSecurityManager(this.getSecurityManager());
		shiroFilterFactoryBean.setFilters(filterManager.getAllFilters());
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterManager.getAllFilterChain());
		this.shiroFilterFactoryBean = shiroFilterFactoryBean;
	}
	

	
	protected void build() {	
		if(!initialized.getAndSet(Boolean.TRUE)){
			this.buildSecurityManager();
			this.buildShiroFilterFactoryBean();
			afterBuild();
		}
	}
	
	private void afterBuild(){
		ShiroUtils.setCryptoService(this.cryptoService);
		ShiroUtils.setFilterManager(this.filterManager);
		ShiroUtils.setRealmManager(this.realmManager);
		ShiroUtils.setSessionManager(this.sessionManager);
		ShiroUtils.setShiroCacheDelegator(this.cacheDelegator);
		ShiroUtils.setShiroFilterFactoryBean(this.shiroFilterFactoryBean);
		ShiroUtils.setShiroProperties(this.properties);
	}


	public ShiroProperties getProperties() {
		return properties;
	}
	public CacheManager getCacheManager() {
		return cacheManager;
	}
	public CacheDelegator getCacheDelegator() {
		return cacheDelegator;
	}
	public JsetsPasswdMatcher getPasswdMatcher() {
		return passwdMatcher;
	}
	public RealmManager getRealmManager() {
		return realmManager;
	}
	public ShiroCryptoService getCryptoService() {
		return cryptoService;
	}
	public void setRedisConnectionFactory(RedisConnectionFactory redisConnectionFactory) {
		this.redisConnectionFactory = redisConnectionFactory;
	}
	public short getCacheType() {
		return cacheType;
	}
	public void setCacheType(short cacheType) {
		this.cacheType = cacheType;
	}
	public DefaultWebSessionManager getSessionManager() {
		return sessionManager;
	}
	public void setCryptoService(ShiroCryptoService cryptoService) {
		this.cryptoService = cryptoService;
	}
	public DefaultWebSecurityManager getSecurityManager() {
		return securityManager;
	}
	public FilterManager getFilterManager() {
		return filterManager;
	}
	public SecurityManagerConfig getManagerConfig() {
		return managerConfig;
	}
	public FilterChainConfig getFilterConfig() {
		return filterConfig;
	}
	public ShiroFilterFactoryBean getShiroFilterFactoryBean() {
		return shiroFilterFactoryBean;
	}
}