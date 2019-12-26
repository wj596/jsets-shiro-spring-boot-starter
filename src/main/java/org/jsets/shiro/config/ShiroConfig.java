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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import javax.servlet.Filter;
import org.apache.commons.collections.MapUtils;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.api.CaptchaProvider;
import org.jsets.shiro.api.PasswordProvider;
import org.jsets.shiro.api.ShiroAccountProvider;
import org.jsets.shiro.api.ShiroCustomizer;
import org.jsets.shiro.api.ShiroFilteRulesProvider;
import org.jsets.shiro.api.ShiroStatelessAccountProvider;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.cache.MapCacheManager;
import org.jsets.shiro.cache.RedisCacheManager;
import org.jsets.shiro.config.internal.DefaultCaptchaProvider;
import org.jsets.shiro.config.internal.DefaultPasswordProvider;
import org.jsets.shiro.config.internal.DefaultShiroAccountProvider;
import org.jsets.shiro.config.internal.DefaultShiroStatelessAccountProvider;
import org.jsets.shiro.filter.ForceLogoutFilter;
import org.jsets.shiro.filter.JcaptchaFilter;
import org.jsets.shiro.filter.JsetsFormAuthenticationFilter;
import org.jsets.shiro.filter.JsetsLogoutFilter;
import org.jsets.shiro.filter.JsetsPermissionsAuthorizationFilter;
import org.jsets.shiro.filter.JsetsRolesAuthorizationFilter;
import org.jsets.shiro.filter.JsetsUserFilter;
import org.jsets.shiro.filter.KeepOneUserFilter;
import org.jsets.shiro.filter.stateless.HmacAuthcFilter;
import org.jsets.shiro.filter.stateless.HmacPermsFilter;
import org.jsets.shiro.filter.stateless.HmacRolesFilter;
import org.jsets.shiro.filter.stateless.JwtAuthcFilter;
import org.jsets.shiro.filter.stateless.JwtPermsFilter;
import org.jsets.shiro.filter.stateless.JwtRolesFilter;
import org.jsets.shiro.listener.AuthListenerManager;
import org.jsets.shiro.listener.DefaultSessionListener;
import org.jsets.shiro.listener.PasswdRetryLimitListener;
import org.jsets.shiro.model.AuthorizeRule;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.RolePermRule;
import org.jsets.shiro.realm.BooleanMatcher;
import org.jsets.shiro.realm.HmacRealm;
import org.jsets.shiro.realm.JwtRealm;
import org.jsets.shiro.realm.UsernamePasswordRealm;
import org.jsets.shiro.realm.UsernameRealm;
import org.jsets.shiro.util.CommonUtils;
import org.jsets.shiro.util.RedisUtils;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import com.google.common.collect.Maps;

/**
 * shiro配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class ShiroConfig {

	private ShiroProperties properties;
	private ShiroCustomizer customizer;
	private org.springframework.cache.CacheManager springCacheManager;
	private DefaultWebSessionManager sessionManager;
	private RememberMeManager rememberMeManager;
	private CacheManager cacheManager;
	private CacheDelegator cacheDelegator;
	private PasswordProvider passwordProvider;
	private CaptchaProvider captchaProvider;
	private ShiroAccountProvider accountProvider;
	private ShiroStatelessAccountProvider statelessAccountProvider;
	private ShiroFilteRulesProvider rulesProvider;
	private PasswdRetryLimitListener limitListener;
	private final CredentialsMatcher booleanMatcher = new BooleanMatcher();
	private final Map<String,Realm> realms = Maps.newHashMap();
	private final Map<String, Filter> filters = Maps.newHashMap();
	private final Map<String, String> staticFilteRules = Maps.newLinkedHashMap();
	private final Map<String, String> dynamicFilteRules = Maps.newLinkedHashMap();
	private final Object reloadMonitor = new Object();

	protected void afterPropertiesSet() {
		
		if(Objects.isNull(this.customizer)) {
			this.customizer = new ShiroCustomizer();
		}
		this.captchaProvider = this.customizer.getCaptchaProvider();
		if(Objects.isNull(this.captchaProvider)) {
			this.captchaProvider = new DefaultCaptchaProvider();
		}
		this.passwordProvider = this.customizer.getPasswordProvider();
		if(Objects.isNull(this.passwordProvider)) {
			this.passwordProvider = new DefaultPasswordProvider(this.properties);
		}
		this.accountProvider = this.customizer.getShiroAccountProvider();
		if(Objects.isNull(this.accountProvider)) 
			this.accountProvider = new DefaultShiroAccountProvider();
		this.statelessAccountProvider = this.customizer.getShiroStatelessAccountProvider();
		if(Objects.isNull(this.statelessAccountProvider)) 
			this.statelessAccountProvider = new DefaultShiroStatelessAccountProvider(this.accountProvider);
		this.limitListener = this.customizer.getPasswdRetryLimitListener();
		this.rulesProvider = this.customizer.getShiroFilteRulesProvider();
		
		biuldSessionManager();
		biuldRememberMeManager();
		biuldCacheManager();
		biuldRealms();
		biuldFilters();
		biuldFilteRules();
	}

	private void biuldSessionManager() {
		
		SessionDAO sessionDAO = this.customizer.getSessionDAO();
		if(Objects.isNull(sessionDAO)) sessionDAO = new EnterpriseCacheSessionDAO();
		List<SessionListener> sessionListeners = this.customizer.getSessionListeners();
		
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(this.properties.getSessionTimeout());
		sessionManager.setSessionIdUrlRewritingEnabled(Boolean.FALSE);
		sessionManager.setSessionValidationInterval(this.properties.getSessionValidationInterval());
		sessionManager.setSessionDAO(sessionDAO);
		sessionManager.getSessionListeners().addAll(sessionListeners);
		sessionManager.getSessionListeners().add(new DefaultSessionListener());
		this.sessionManager = sessionManager;
	}
	
	private void biuldRememberMeManager() {
		
		Cookie rememberMeCookie = this.customizer.getRememberMeCookie();
		if(Objects.isNull(rememberMeCookie)) {
			rememberMeCookie = new SimpleCookie();
			rememberMeCookie.setName(CommonUtils.REMEMBERME_COOKIE_NAME);
			rememberMeCookie.setHttpOnly(Boolean.TRUE);
			rememberMeCookie.setMaxAge(this.properties.getRemembermeMaxAge());
		}
		
		CookieRememberMeManager rememberMeManager =  new CookieRememberMeManager();
		rememberMeManager.setCipherKey(CodecSupport.toBytes(this.properties.getRemembermeSecretKey()));
		rememberMeManager.setCookie(rememberMeCookie);
		this.rememberMeManager = rememberMeManager;
	}
	
	private void biuldCacheManager() {
		
		this.cacheManager = this.customizer.getCacheManager();
		if(Objects.isNull(this.cacheManager)) {
			if(Objects.isNull(springCacheManager)) {
				this.cacheManager = new MapCacheManager();
			}else {
				if (springCacheManager instanceof EhCacheCacheManager) {
					EhCacheManager ehCacheManager = new EhCacheManager();
					ehCacheManager.setCacheManager(((EhCacheCacheManager) springCacheManager).getCacheManager());
					this.cacheManager = ehCacheManager;
				}
				if (springCacheManager instanceof org.springframework.data.redis.cache.RedisCacheManager) {
					RedisCacheManager redisCacheManager = new RedisCacheManager();
					redisCacheManager.setRedisTemplate(RedisUtils.imitateRedisTemplate());
					this.cacheManager = redisCacheManager;
				}
			}
		}
		this.cacheDelegator = new CacheDelegator(this.cacheManager);
	}
	
	private void biuldRealms() {
		
		Map<String,Realm> customizedRealms = this.customizer.getRealms();
		
		UsernamePasswordRealm usernamePasswordRealm = new UsernamePasswordRealm(
				this.properties,this.cacheDelegator,this.accountProvider,this.limitListener);
		usernamePasswordRealm.setCredentialsMatcher(booleanMatcher);
		if (this.properties.isAuthCacheEnabled()) {
			usernamePasswordRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
			usernamePasswordRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
			usernamePasswordRealm.setCachingEnabled(Boolean.TRUE);
			usernamePasswordRealm.setAuthenticationCachingEnabled(Boolean.TRUE);
			usernamePasswordRealm.setAuthorizationCachingEnabled(Boolean.TRUE);
		}  else {
			usernamePasswordRealm.setCachingEnabled(Boolean.FALSE);
		}
		this.realms.put("usernamePasswordRealm", usernamePasswordRealm);
		
		if (this.properties.isHmacEnabled()) {
			HmacRealm hmacRealm = new HmacRealm(
								this.properties,this.cacheDelegator,this.statelessAccountProvider);
			hmacRealm.setCredentialsMatcher(booleanMatcher);
			hmacRealm.setCachingEnabled(Boolean.FALSE);
			this.realms.put("hmacRealm", hmacRealm);
		}
		
		if (this.properties.isJwtEnabled()) {
			JwtRealm jwtRealm = new JwtRealm(
								this.properties,this.cacheDelegator,this.statelessAccountProvider);
			jwtRealm.setCredentialsMatcher(booleanMatcher);
			jwtRealm.setCachingEnabled(Boolean.FALSE);	
			this.realms.put("jwtRealm", jwtRealm);
		}
		
		if (this.properties.isFreePasswordEnabled()||this.properties.isJssoClient()) {
			UsernameRealm usernameRealm = new UsernameRealm(this.properties,this.accountProvider);
			usernameRealm.setCredentialsMatcher(booleanMatcher);
			usernameRealm.setCachingEnabled(Boolean.FALSE);	
			this.realms.put("usernameRealm", usernameRealm);
		}

		if(MapUtils.isNotEmpty(customizedRealms)) {
			boolean errorExist = customizedRealms.values().stream()
					.filter(r-> (r instanceof AuthenticatingRealm))
					.anyMatch(r->Objects.isNull(((AuthenticatingRealm)r).getCredentialsMatcher()));
			if(errorExist) 
				throw new IllegalConfigException("Realm 必须有对应的CredentialsMatcher");
			customizedRealms.forEach((k,v)->this.realms.put(k, v));
		}
	}
	
	private void biuldFilters() {
		
		Map<String,Filter> customizedFilters = this.customizer.getFilters();
		AuthListenerManager authListenerManager = this.customizer.getAuthListenerManager();
		
		if (this.properties.isJcaptchaEnable()) {
			JcaptchaFilter jcaptchaFilter = new JcaptchaFilter(this.captchaProvider);
			this.filters.putIfAbsent(CommonUtils.FILTER_JCAPTCHA, jcaptchaFilter);
		}
		if (this.properties.isKeepOneEnabled()) {
			KeepOneUserFilter keepOneFilter  = new KeepOneUserFilter(properties,cacheDelegator,sessionManager,authListenerManager);
			this.filters.putIfAbsent(CommonUtils.FILTER_KEEP_ONE, keepOneFilter);
		}
		if (this.properties.isForceLogoutEnable()) {
			ForceLogoutFilter forceFilter = new ForceLogoutFilter(this.properties,authListenerManager);
			this.filters.putIfAbsent(CommonUtils.FILTER_FORCE_LOGOUT, forceFilter);
		}
		if (this.properties.isHmacEnabled()) {
			HmacAuthcFilter hmacFilter = new HmacAuthcFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_HMAC, hmacFilter);
			HmacRolesFilter hmacRolesFilter = new HmacRolesFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_HMAC_ROLES, hmacRolesFilter);
			HmacPermsFilter hmacPermsFilter = new HmacPermsFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_HMAC_PERMS, hmacPermsFilter);
		}
		if (this.properties.isJwtEnabled()) {
			JwtAuthcFilter jwtFilter = new JwtAuthcFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_JWT, jwtFilter);
			JwtRolesFilter jwtRolesFilter = new JwtRolesFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_JWT_ROLES, jwtRolesFilter);
			JwtPermsFilter jwtPermsFilter = new JwtPermsFilter();
			this.filters.putIfAbsent(CommonUtils.FILTER_JWT_PERMS, jwtPermsFilter);
		}
		
		this.filters.putIfAbsent(CommonUtils.FILTER_AUTHC, new JsetsFormAuthenticationFilter(this.properties,this.captchaProvider,authListenerManager));
		this.filters.putIfAbsent(CommonUtils.FILTER_LOGOUT, new JsetsLogoutFilter(authListenerManager));
		this.filters.putIfAbsent(CommonUtils.FILTER_ROLES, new JsetsRolesAuthorizationFilter(authListenerManager));
		this.filters.putIfAbsent(CommonUtils.FILTER_PERMS, new JsetsPermissionsAuthorizationFilter());
		this.filters.putIfAbsent(CommonUtils.FILTER_USER, new JsetsUserFilter(this.accountProvider));
	
		if(MapUtils.isNotEmpty(customizedFilters)) 
			customizedFilters.forEach((k,v)->this.filters.put(k, v));
	}
	
	private void biuldFilteRules() {
		this.biuldStaticFilteRules();
		this.biuldDynamicFilteRules();
	}

	private void biuldStaticFilteRules() {
		
		ShiroProperties.DEFAULT_IGNORED
			.forEach(ignored -> this.staticFilteRules.put(ignored, CommonUtils.FILTER_ANON));
		if(CommonUtils.hasLen(this.properties.getKickoutUrl()))
			this.staticFilteRules.put(properties.getKickoutUrl(), CommonUtils.FILTER_ANON);
		if(CommonUtils.hasLen(properties.getForceLogoutUrl()))
			this.staticFilteRules.put(properties.getForceLogoutUrl(), CommonUtils.FILTER_ANON);
		if (this.properties.isJcaptchaEnable())
			this.staticFilteRules.put(CommonUtils.JCAPTCHA_URL, CommonUtils.FILTER_JCAPTCHA);
		if(!this.properties.getFilteRules().isEmpty())
			this.properties.getFilteRules().forEach(rule->{
				if(rule.split("-->").length!=2) 
					throw new IllegalConfigException("过滤规则配置不正确,格式：url->filters");
				Stream.of(rule.split("-->")[0].split(","))
					.forEach(url->this.staticFilteRules.put(url, rule.split("-->")[1]));
		});
	}
	
	private void attachFilters(StringBuilder filterChain){
		if (this.properties.isJssoClient()) 
			filterChain.append(","+CommonUtils.FILTER_JSSO_CLIENT);
		filterChain.append(","+CommonUtils.FILTER_USER);
		if (this.properties.isKeepOneEnabled()) 
			filterChain.append(","+CommonUtils.FILTER_KEEP_ONE);
		if (this.properties.isForceLogoutEnable()) 
			filterChain.append(","+CommonUtils.FILTER_FORCE_LOGOUT);
	}
	
	private void biuldDynamicFilteRules() {

		if(Objects.nonNull(this.rulesProvider)) {
			this.dynamicFilteRules.clear();
			List<RolePermRule> rolePermRules = this.rulesProvider.loadRolePermRules();
			if(null != rolePermRules)
				rolePermRules.forEach(rule -> {
					rule.setType(AuthorizeRule.RULE_TYPE_DEF);
					StringBuilder filterChain = rule.toFilterChain();
					if(null != filterChain){
						this.attachFilters(filterChain);
						this.dynamicFilteRules.putIfAbsent(rule.getUrl(), filterChain.toString());
					}
				}); 
			
			List<RolePermRule> hmacRules = rulesProvider.loadHmacRules();
			if(null != hmacRules)
				hmacRules.forEach(rule -> {
					rule.setType(AuthorizeRule.RULE_TYPE_HMAC);
					StringBuilder filterChain = rule.toFilterChain();
					if(null != filterChain)
						this.dynamicFilteRules.putIfAbsent(rule.getUrl(), filterChain.toString());
				}); 

			List<RolePermRule> jwtRules = rulesProvider.loadJwtRules();
			if(null != jwtRules)
				jwtRules.forEach(rule -> {
					rule.setType(AuthorizeRule.RULE_TYPE_JWT);
					StringBuilder filterChain = rule.toFilterChain();
					if(null != filterChain)
						this.dynamicFilteRules.putIfAbsent(rule.getUrl(), filterChain.toString());
				}); 
			
			List<CustomRule> customRules = rulesProvider.loadCustomRules();
			if(null != customRules)
				customRules.forEach(rule -> {
					rule.setType(AuthorizeRule.RULE_TYPE_CUSTOM);
					StringBuilder filterChain = rule.toFilterChain();
					if(null != filterChain){
						this.attachFilters(filterChain);
						this.dynamicFilteRules.putIfAbsent(rule.getUrl(), filterChain.toString());
					}
			});
		}
	}
	
	public void reloadFilterRules(ShiroFilterFactoryBean factoryBean) {
		synchronized (this.reloadMonitor) {
			AbstractShiroFilter abstractShiroFilter = null;
			try {
				abstractShiroFilter = (AbstractShiroFilter) factoryBean.getObject();
				PathMatchingFilterChainResolver filterChainResolver = (PathMatchingFilterChainResolver) abstractShiroFilter.getFilterChainResolver();
				DefaultFilterChainManager filterChainManager = (DefaultFilterChainManager) filterChainResolver.getFilterChainManager();
				filterChainManager.getFilterChains().clear();
				factoryBean.getFilterChainDefinitionMap().clear();
				this.biuldDynamicFilteRules();
				factoryBean.setFilterChainDefinitionMap(this.getRules());
				factoryBean.getFilterChainDefinitionMap().forEach((k,v) -> filterChainManager.createChain(k, v));
			} catch (Exception e) {
				throw new RuntimeException(e.getMessage(),e);
			}
		}
	}
	
	
	
	
	protected void setProperties(ShiroProperties properties) {
		this.properties = properties;
	}
	protected void setCustomizer(ShiroCustomizer customizer) {
		this.customizer = customizer;
	}
	protected void setSpringCacheManager(org.springframework.cache.CacheManager springCacheManager) {
		this.springCacheManager = springCacheManager;
	}
	
	
	
	public DefaultWebSessionManager getSessionManager() {
		return this.sessionManager;
	}
	
	public RememberMeManager getRememberMeManager() {
		return this.rememberMeManager;
	}
	
	public CacheManager getCacheManager() {
		return this.cacheManager;
	}
	
	public Collection<Realm> getRealms() {
		return this.realms.values();
	}
	
	public Map<String, Filter> getFilters() {
		return this.filters;
	}

	public Map<String, String> getRules() {
		Map<String, String> rules = Maps.newLinkedHashMap();
		rules.putAll(Collections.unmodifiableMap(this.dynamicFilteRules));
		rules.putAll(Collections.unmodifiableMap(this.staticFilteRules));
		return rules;
	}
	
	public PasswordProvider getPasswordProvider() {
		return this.passwordProvider;
	}
	
	public CacheDelegator getCacheDelegator() {
		return this.cacheDelegator;
	}
	
	
}