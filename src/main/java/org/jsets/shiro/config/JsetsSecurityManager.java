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
import java.util.Map;
import javax.servlet.Filter;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.authc.JsetsHmacMatcher;
import org.jsets.shiro.authc.JsetsJwtMatcher;
import org.jsets.shiro.authc.JsetsPasswdMatcher;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.cache.MapCacheManager;
import org.jsets.shiro.cache.RedisCacheManager;
import org.jsets.shiro.filter.ForceLogoutFilter;
import org.jsets.shiro.filter.JcaptchaFilter;
import org.jsets.shiro.filter.JsetsFormAuthenticationFilter;
import org.jsets.shiro.filter.JsetsPermissionsAuthorizationFilter;
import org.jsets.shiro.filter.JsetsRolesAuthorizationFilter;
import org.jsets.shiro.filter.JsetsUserFilter;
import org.jsets.shiro.filter.KeepOneUserFilter;
import org.jsets.shiro.filter.stateless.HmacAuthcFilter;
import org.jsets.shiro.filter.stateless.HmacRolesFilter;
import org.jsets.shiro.filter.stateless.JwtAuthcFilter;
import org.jsets.shiro.handler.DefaultSessionListener;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.HmacRule;
import org.jsets.shiro.model.JwtRule;
import org.jsets.shiro.model.RolePermRule;
import org.jsets.shiro.realm.HmacRealm;
import org.jsets.shiro.realm.JwtRealm;
import org.jsets.shiro.realm.AccountPasswdRealm;
import org.jsets.shiro.service.DefaultShiroStatelessAccountProviderImpl;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * 安全管理器构造器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsSecurityManager {
	
	private JsetsSecurityManager(){};
	private static class SecurityManagerBuilderHolder{
		private static JsetsSecurityManager securityManagerBuilder = new JsetsSecurityManager();
	}
	protected static JsetsSecurityManager getInstance(){
		  return SecurityManagerBuilderHolder.securityManagerBuilder;
	}
	
	private static final Logger LOGGER = LoggerFactory.getLogger(JsetsSecurityManager.class);
	
	private static final String FILTER_ANON = "anon";
	private static final String FILTER_AUTHC = "authc";
	private static final String FILTER_JCAPTCHA = "jcaptcha";
	private static final String FILTER_ROLES = "roles";
	private static final String FILTER_PERMS = "perms";
	private static final String FILTER_USER = "user";
	private static final String FILTER_KEEP_ONE = "keepOne";
	private static final String FILTER_FORCE_LOGOUT = "forceLogout";
	private static final String FILTER_HMAC = "hmac";
	private static final String FILTER_HMAC_ROLES = "hmacRoles";
	private static final String FILTER_HMAC_PERMS = "hmacRoles";
	private static final String FILTER_JWT = "jwt";
	private static final String FILTER_JWT_ROLES = "hmacRoles";
	private static final String FILTER_JWT_PERMS = "hmacRoles";
	
	private SecurityManagerConfig securityConfig;
	private FilterChainConfig filterChainConfig;
	private DefaultWebSessionManager sessionManager;
	private CacheDelegator cacheDelegator;
	private String additionFilters;
	private ShiroFilterFactoryBean shiroFilterFactoryBean;
	private final List<Realm> cachedRealms = Lists.newLinkedList();
	private final Map<String, String> anonRules = Maps.newLinkedHashMap();
	private final Map<String, String> staticRules = Maps.newLinkedHashMap();
	private final Object reloadFilterRulesMonitor = new Object();
	

	protected void decideSessionDAO() {
		if(null != this.securityConfig.getSessionDAO()){
			this.getSessionManager().setSessionDAO(this.securityConfig.getSessionDAO());
		}else{
			SessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
			this.getSessionManager().setSessionDAO(sessionDAO);
		}
	}
	
	protected void decideSessionListeners() {
		DefaultSessionListener defSessionListener = new DefaultSessionListener();
		List<SessionListener> listeners = this.securityConfig.getSessionListeners();
		listeners.add(defSessionListener);
		this.sessionManager.setSessionListeners(listeners);
	}
	
	
	protected void decideRememberMeCookie(final ShiroProperties properties
									,final CookieRememberMeManager rememberMeManager) {
		if (null != this.getSecurityConfig().getRememberMeCookie()) {
			rememberMeManager.setCookie(this.getSecurityConfig().getRememberMeCookie());
		} else {
			SimpleCookie simpleCookie = new SimpleCookie();
			simpleCookie.setName("rememberMeCookie");
			simpleCookie.setHttpOnly(Boolean.TRUE);
			simpleCookie.setMaxAge(properties.getRemembermeMaxAge());
			rememberMeManager.setCookie(simpleCookie);
		}
	}
	
	
	protected CacheManager decideCacheManager(final ShiroProperties properties,final RedisConnectionFactory redisConnectionFactory) {
		if (null != this.getSecurityConfig().getCacheManager()) {
			return this.getSecurityConfig().getCacheManager();
		} else {
			boolean enabledEhcache = properties.isEhcacheEnabled();
			boolean enabledRedis = properties.isRedisEnabled();
			if (enabledEhcache && enabledRedis) {
				enabledRedis = Boolean.FALSE;
			}
			if (enabledEhcache && !Strings.isNullOrEmpty(properties.getEhcacheConfigFile())) {
				EhCacheManager ehCacheManager = new EhCacheManager();
				ehCacheManager.setCacheManagerConfigFile(properties.getEhcacheConfigFile());
				return ehCacheManager;
			} else if (enabledRedis && null != redisConnectionFactory) {
				RedisCacheManager redisCacheManager = new RedisCacheManager();

				GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();  
				RedisTemplate<Object, Object> redisTemplate = new RedisTemplate<Object, Object>();
				redisTemplate.setConnectionFactory(redisConnectionFactory);
				redisTemplate.setKeySerializer(jsonSerializer);
				redisTemplate.setHashKeySerializer(jsonSerializer);
				redisTemplate.setBeanClassLoader(this.getClass().getClassLoader());
				redisTemplate.afterPropertiesSet();
				redisCacheManager.setRedisTemplate(redisTemplate);
				return redisCacheManager;
			} else {
				return new MapCacheManager();
			}
		}
	}
	
	
	protected void decideRealms(final ShiroProperties properties, final DefaultWebSecurityManager securityManager,
										final ShiroCryptoService cryptoService, final CacheDelegator cacheDelegator) {

		List<Realm> useRealms = Lists.newLinkedList();
		JsetsPasswdMatcher passwdMatcher = new JsetsPasswdMatcher(properties,cacheDelegator,cryptoService
															  ,this.getSecurityConfig().getPasswdRetryLimitHandler());
		
		AccountPasswdRealm accountPasswdRealm = new AccountPasswdRealm(this.getSecurityConfig().getAccountProvider());
		accountPasswdRealm.setCredentialsMatcher(passwdMatcher);
		if (properties.isAuthCacheEnabled()) {
			accountPasswdRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
			accountPasswdRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
			accountPasswdRealm.setAuthenticationCachingEnabled(Boolean.TRUE);
			accountPasswdRealm.setAuthorizationCachingEnabled(Boolean.TRUE);
			accountPasswdRealm.setCachingEnabled(Boolean.TRUE);
			this.cachedRealms.add(accountPasswdRealm);
		} else {
			accountPasswdRealm.setCachingEnabled(Boolean.FALSE);
		}
		useRealms.add(accountPasswdRealm);

		if (properties.isHmacEnabled()) {
			ShiroStatelessAccountProvider accountProvider = null;
			if (null == this.getSecurityConfig().getStatelessAccountProvider()) {
				accountProvider = 
					new DefaultShiroStatelessAccountProviderImpl(this.getSecurityConfig().getAccountProvider());
			}
			JsetsHmacMatcher hmacMatcher = new JsetsHmacMatcher(properties,cryptoService,accountProvider);
			HmacRealm hmacRealm = new HmacRealm(accountProvider);
			hmacRealm.setCredentialsMatcher(hmacMatcher);
			hmacRealm.setCachingEnabled(Boolean.FALSE);
			useRealms.add(hmacRealm);
		}
		if (properties.isJwtEnabled()) {
			JsetsJwtMatcher jwtMatcher = new JsetsJwtMatcher(cryptoService);
			JwtRealm jwtRealm = new JwtRealm();
			jwtRealm.setCredentialsMatcher(jwtMatcher);
			jwtRealm.setCachingEnabled(Boolean.FALSE);
			useRealms.add(jwtRealm);
		}
		for (Realm realm : this.getSecurityConfig().getRealms()) {
			if (realm instanceof AuthorizingRealm && properties.isAuthCacheEnabled()) {
				AuthorizingRealm authorizingRealm = (AuthorizingRealm) realm;
				authorizingRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
				authorizingRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
				authorizingRealm.setAuthenticationCachingEnabled(Boolean.TRUE);
				authorizingRealm.setAuthorizationCachingEnabled(Boolean.TRUE);
				authorizingRealm.setCachingEnabled(Boolean.TRUE);
				this.cachedRealms.add(accountPasswdRealm);
				useRealms.add(authorizingRealm);
			} else {
				useRealms.add(realm);
			}
		}
		securityManager.setRealms(useRealms);
	}
	
	protected void decideFixations(final ShiroProperties properties){
		if(!Strings.isNullOrEmpty(properties.getLoginUrl()))
			this.getShiroFilterFactoryBean().setLoginUrl(properties.getLoginUrl());
		if(!Strings.isNullOrEmpty(properties.getLoginSuccessUrl())) 
			this.getShiroFilterFactoryBean().setSuccessUrl(properties.getLoginSuccessUrl());
		if(!Strings.isNullOrEmpty(properties.getUnauthorizedUrl())) 
			this.getShiroFilterFactoryBean().setUnauthorizedUrl(properties.getUnauthorizedUrl());
	}
	
	protected void decideFilters(final ShiroProperties properties) {
		Map<String, Filter> filters = Maps.newLinkedHashMap();
		filters.putAll(this.filterChainConfig.getFilters());
		
		JsetsFormAuthenticationFilter formAuthenticationFilter = new JsetsFormAuthenticationFilter(properties);
		filters.putIfAbsent(FILTER_AUTHC, formAuthenticationFilter);
		if (properties.isJcaptchaEnable()) {
			JcaptchaFilter jcaptchaFilter = new JcaptchaFilter();
			filters.putIfAbsent(FILTER_JCAPTCHA, jcaptchaFilter);
		}
		JsetsRolesAuthorizationFilter rolesAuthorizationFilter = new JsetsRolesAuthorizationFilter();
		filters.putIfAbsent(FILTER_ROLES, rolesAuthorizationFilter);
		JsetsPermissionsAuthorizationFilter permissionsAuthorizationFilter = new JsetsPermissionsAuthorizationFilter();
		filters.putIfAbsent(FILTER_PERMS, permissionsAuthorizationFilter);
		JsetsUserFilter userFilter = new JsetsUserFilter(this.getSecurityConfig().getAccountProvider());
		filters.putIfAbsent(FILTER_USER, userFilter);
		if (properties.isKeepOneEnabled()) {
			KeepOneUserFilter keepOneUserFilter = new KeepOneUserFilter(properties,this.getSessionManager(),this.getCacheDelegator());
			filters.putIfAbsent(FILTER_KEEP_ONE, keepOneUserFilter);
		}
		if (properties.isForceLogoutEnable()) {
			ForceLogoutFilter forceLogoutFilter = new ForceLogoutFilter(properties);
			filters.putIfAbsent(FILTER_FORCE_LOGOUT, forceLogoutFilter);
		}
		if (properties.isHmacEnabled()) {
			HmacAuthcFilter hmacFilter = new HmacAuthcFilter();
			filters.putIfAbsent(FILTER_HMAC, hmacFilter);
			HmacRolesFilter hmacRolesFilter = new HmacRolesFilter();
			filters.putIfAbsent(FILTER_HMAC_ROLES, hmacRolesFilter);
		}
		if (properties.isHmacEnabled()) {
			JwtAuthcFilter jwtFilter = new JwtAuthcFilter();
			filters.putIfAbsent(FILTER_JWT, jwtFilter);
		}
		this.getShiroFilterFactoryBean().setFilters(filters);
	}
	
	protected void decideFilteRules(final ShiroProperties properties) {
		// ------------anon
		for (String ignored : ShiroProperties.DEFAULT_IGNORED) {
			this.getAnonRules().putIfAbsent(ignored, FILTER_ANON);
		}
		if(!Strings.isNullOrEmpty(properties.getKickoutUrl()))
			this.getAnonRules().put(properties.getKickoutUrl(), FILTER_ANON);
		if(!Strings.isNullOrEmpty(properties.getForceLogoutUrl()))
			this.getAnonRules().put(properties.getForceLogoutUrl(), FILTER_ANON);
		// ------------static
		for (String rules : properties.getFilteRules()) {
			String urls = rules.split("-->")[0];
			String filters = rules.split("-->")[1];
			for (String url : urls.split(",")) {
				this.getStaticRules().putIfAbsent(url, filters);
			}
		}
		// ------------dynamic
		StringBuilder additions = new StringBuilder();
		additions.append(",");
		additions.append(FILTER_USER);
		if (properties.isKeepOneEnabled()) {
			additions.append(",");
			additions.append(FILTER_KEEP_ONE);
		}
		if (properties.isForceLogoutEnable()) {
			additions.append(",");
			additions.append(FILTER_FORCE_LOGOUT);
		}
		this.setAdditionFilters(additions.toString());
		Map<String, String> filterChainDefinitionMap = Maps.newLinkedHashMap();
		filterChainDefinitionMap.putAll(this.getAnonRules());
		filterChainDefinitionMap.putAll(this.getDynamicRules());
		if (properties.isJcaptchaEnable())
			filterChainDefinitionMap.put(ShiroProperties.DEFAULT_JCAPTCHA_URL, FILTER_JCAPTCHA);
		filterChainDefinitionMap.putAll(this.getStaticRules());
		this.getShiroFilterFactoryBean().setFilterChainDefinitionMap(filterChainDefinitionMap);
	}

	public void reloadFilterRules(final ShiroProperties properties) {
		synchronized (reloadFilterRulesMonitor) {
			AbstractShiroFilter abstractShiroFilter = null;
			try {
				abstractShiroFilter = (AbstractShiroFilter) this.getShiroFilterFactoryBean().getObject();
				PathMatchingFilterChainResolver filterChainResolver = (PathMatchingFilterChainResolver) abstractShiroFilter
						.getFilterChainResolver();
				DefaultFilterChainManager filterChainManager = (DefaultFilterChainManager) filterChainResolver
						.getFilterChainManager();
				filterChainManager.getFilterChains().clear();
				this.getShiroFilterFactoryBean().getFilterChainDefinitionMap().clear();
				Map<String, String> filterChainDefinitionMap = Maps.newLinkedHashMap();
				filterChainDefinitionMap.putAll(this.getAnonRules());
				filterChainDefinitionMap.putAll(this.getDynamicRules());
				if (properties.isJcaptchaEnable())
					filterChainDefinitionMap.put(ShiroProperties.DEFAULT_JCAPTCHA_URL, FILTER_JCAPTCHA);
				filterChainDefinitionMap.putAll(this.getStaticRules());
				this.getShiroFilterFactoryBean().setFilterChainDefinitionMap(filterChainDefinitionMap);
				for (String url : filterChainDefinitionMap.keySet()) {
					filterChainManager.createChain(url, filterChainDefinitionMap.get(url));
				}
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
	}
	
	
	protected Map<String, String> getDynamicRules() {
		ShiroFilteRulesProvider filteRulesProvider = this.filterChainConfig.getShiroFilteRulesProvider();
		Map<String, String> dynamicRules = Maps.newLinkedHashMap();
		if(null == filteRulesProvider) return dynamicRules;
		List<RolePermRule> rolePermRules = filteRulesProvider.loadRolePermRules();
		List<HmacRule> hmacRules = filteRulesProvider.loadHmacRules();
		List<JwtRule> jwtRules = filteRulesProvider.loadJwtRules();
		List<CustomRule> customRules = filteRulesProvider.loadCustomRules();
		if(null!=rolePermRules&&!rolePermRules.isEmpty()){
            for(RolePermRule rolePermRule : rolePermRules){
            	if(Strings.isNullOrEmpty(rolePermRule.getUrl())) continue;
            	StringBuilder sb = new StringBuilder();
            	if(!Strings.isNullOrEmpty(rolePermRule.getNeedRoles())){
            		sb.append(FILTER_ROLES+"["+rolePermRule.getNeedRoles()+"]");
            	}
            	if(!Strings.isNullOrEmpty(rolePermRule.getNeedPerms())){
            		if(sb.length()>0) sb.append(",");
            		sb.append(FILTER_PERMS+"["+rolePermRule.getNeedRoles()+"]");
            	}
            	if(sb.length()==0) continue;
            	sb.append(this.getAdditionFilters());
            	dynamicRules.putIfAbsent(rolePermRule.getUrl(), sb.toString());
    		}
		}

		if(null!=hmacRules&&!hmacRules.isEmpty()){
            for(HmacRule hmacRule : hmacRules){
            	if(Strings.isNullOrEmpty(hmacRule.getUrl())) continue;
            	StringBuilder sb = new StringBuilder();
            	if(!Strings.isNullOrEmpty(hmacRule.getNeedRoles())){
            		sb.append(FILTER_HMAC_ROLES+"["+hmacRule.getNeedRoles()+"]");
            	}
            	if(!Strings.isNullOrEmpty(hmacRule.getNeedPerms())){
            		if(sb.length()>0) sb.append(",");
            		sb.append(FILTER_HMAC_PERMS+"["+hmacRule.getNeedRoles()+"]");
            	}
            	if(sb.length()==0) {
            		sb.append(FILTER_HMAC);
            	}
            	dynamicRules.putIfAbsent(hmacRule.getUrl(), sb.toString());
    		}
		}
		if(null!=jwtRules&&!jwtRules.isEmpty()){
			for(JwtRule jwtRule : jwtRules){
            	if(Strings.isNullOrEmpty(jwtRule.getUrl())) continue;
            	StringBuilder sb = new StringBuilder();
            	if(!Strings.isNullOrEmpty(jwtRule.getNeedRoles())){
            		sb.append(FILTER_JWT_ROLES+"["+jwtRule.getNeedRoles()+"]");
            	}
            	if(!Strings.isNullOrEmpty(jwtRule.getNeedPerms())){
            		if(sb.length()>0) sb.append(",");
            		sb.append(FILTER_JWT_PERMS+"["+jwtRule.getNeedRoles()+"]");
            	}
            	if(sb.length()==0) {
            		sb.append(FILTER_JWT);
            	}
            	dynamicRules.putIfAbsent(jwtRule.getUrl(), sb.toString());
    		} 
		}
		if(null!=customRules&&!customRules.isEmpty()){
            for(CustomRule customRule : customRules){
            	if(Strings.isNullOrEmpty(customRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(customRule.getRule())) continue;
            	dynamicRules.putIfAbsent(customRule.getUrl(),customRule.getRule()+this.getAdditionFilters());
    		}
		}
		return dynamicRules;
	}
	
	
	
	public SecurityManagerConfig getSecurityConfig() {
		return securityConfig;
	}
	public void setSecurityConfig(SecurityManagerConfig securityConfig) {
		this.securityConfig = securityConfig;
	}
	public FilterChainConfig getFilterChainConfig() {
		return filterChainConfig;
	}
	public void setFilterChainConfig(FilterChainConfig filterChainConfig) {
		this.filterChainConfig = filterChainConfig;
	}
	public DefaultWebSessionManager getSessionManager() {
		return sessionManager;
	}
	public CacheDelegator getCacheDelegator() {
		return cacheDelegator;
	}
	public void setSessionManager(DefaultWebSessionManager sessionManager) {
		if(null!=this.sessionManager){
			throw new UnsupportedOperationException("对象不能覆盖");
		}
		this.sessionManager = sessionManager;
	}
	public void setCacheDelegator(CacheDelegator cacheDelegator) {
		if(null!=this.cacheDelegator){
			throw new UnsupportedOperationException("对象不能覆盖");
		}
		this.cacheDelegator = cacheDelegator;
	}
	protected Map<String, String> getAnonRules() {
		return anonRules;
	}
	protected Map<String, String> getStaticRules() {
		return staticRules;
	}
	protected ShiroFilterFactoryBean getShiroFilterFactoryBean() {
		return shiroFilterFactoryBean;
	}
	protected void setShiroFilterFactoryBean(ShiroFilterFactoryBean shiroFilterFactoryBean) {
		if(null!=this.shiroFilterFactoryBean){
			throw new UnsupportedOperationException("对象不能覆盖");
		}
		this.shiroFilterFactoryBean = shiroFilterFactoryBean;
	}
	protected String getAdditionFilters() {
		return additionFilters;
	}
	protected void setAdditionFilters(String additionFilters) {
		this.additionFilters = additionFilters;
	}
	public List<Realm> getCachedRealms() {
		return cachedRealms;
	}
}