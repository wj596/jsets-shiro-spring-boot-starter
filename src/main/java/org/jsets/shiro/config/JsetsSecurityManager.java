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
import org.jsets.shiro.authc.JsetsBooleanMatcher;
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
import org.jsets.shiro.filter.stateless.JwtFilter;
import org.jsets.shiro.handler.DefaultSessionListener;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.HmacRule;
import org.jsets.shiro.model.JwtRule;
import org.jsets.shiro.model.PermRule;
import org.jsets.shiro.model.RoleRule;
import org.jsets.shiro.realm.HmacRealm;
import org.jsets.shiro.realm.JwtRealm;
import org.jsets.shiro.realm.PasswdRealm;
import org.jsets.shiro.service.DefaultShiroStatelessAccountProviderImpl;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * 安全管理器构造器
 *
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
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
	
	
	protected CacheManager decideCacheManager(final ShiroProperties properties,final RedisTemplate redisTemplate) {
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
			} else if (enabledRedis && null != redisTemplate) {
				RedisCacheManager redisCacheManager = new RedisCacheManager();
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
		JsetsPasswdMatcher passwdMatcher = new JsetsPasswdMatcher(
					properties,cacheDelegator,cryptoService,this.getSecurityConfig().getPasswdRetryLimitHandler());
		JsetsBooleanMatcher booleanMatcher = new JsetsBooleanMatcher();
		PasswdRealm passwdRealm = new PasswdRealm(this.getSecurityConfig().getAccountProvider());
		passwdRealm.setCredentialsMatcher(passwdMatcher);
		if (properties.isAuthCacheEnabled()) {
			passwdRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
			passwdRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
			passwdRealm.setAuthenticationCachingEnabled(Boolean.TRUE);
			passwdRealm.setAuthorizationCachingEnabled(Boolean.TRUE);
			passwdRealm.setCachingEnabled(Boolean.TRUE);
			this.cachedRealms.add(passwdRealm);
		} else {
			passwdRealm.setCachingEnabled(Boolean.FALSE);
		}
		useRealms.add(passwdRealm);

		if (properties.isHmacEnabled()) {
			ShiroStatelessAccountProvider accountProvider = null;
			if (null == this.getSecurityConfig().getStatelessAccountProvider()) {
				accountProvider = 
					new DefaultShiroStatelessAccountProviderImpl(this.getSecurityConfig().getAccountProvider());
			}
			HmacRealm hmacRealm = new HmacRealm(cryptoService, accountProvider);
			hmacRealm.setCredentialsMatcher(booleanMatcher);
			hmacRealm.setCachingEnabled(Boolean.FALSE);
			useRealms.add(hmacRealm);
		}
		if (properties.isJwtEnabled()) {
			JwtRealm jwtRealm = new JwtRealm(cryptoService);
			jwtRealm.setCredentialsMatcher(booleanMatcher);
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
				this.cachedRealms.add(passwdRealm);
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
			JwtFilter jwtFilter = new JwtFilter();
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
		System.out.println(filterChainDefinitionMap);
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
		List<RoleRule> roleRules = filteRulesProvider.loadRoleRules();
		List<PermRule> permRules = filteRulesProvider.loadPermRules();
		List<HmacRule> hmacRules = filteRulesProvider.loadHmacRules();
		List<JwtRule> jwtRules = filteRulesProvider.loadJwtRules();
		List<CustomRule> customRules = filteRulesProvider.loadCustomRules();
		if(null!=roleRules&&!roleRules.isEmpty()){
            for(RoleRule roleRule : roleRules){
            	if(Strings.isNullOrEmpty(roleRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(roleRule.getNeedRoles())) continue;
            	dynamicRules.putIfAbsent(roleRule.getUrl(), FILTER_ROLES+"["+roleRule.getNeedRoles()+"]"+this.getAdditionFilters());
    		}
		}
		if(null!=permRules&&!permRules.isEmpty()){
            for(PermRule permRule : permRules){
            	if(Strings.isNullOrEmpty(permRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(permRule.getNeedPerms())) continue;
            	dynamicRules.putIfAbsent(permRule.getUrl(), FILTER_PERMS+"["+permRule.getNeedPerms()+"]"+this.getAdditionFilters());
    		}
		}
		if(null!=hmacRules&&!hmacRules.isEmpty()){
            for(HmacRule hmacRule : hmacRules){
            	if(Strings.isNullOrEmpty(hmacRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(hmacRule.getNeedRoles())){
            		dynamicRules.putIfAbsent(hmacRule.getUrl(), FILTER_HMAC_ROLES+"["+hmacRule.getNeedRoles()+"]");
            	} else if(Strings.isNullOrEmpty(hmacRule.getNeedPerms())){
            		dynamicRules.putIfAbsent(hmacRule.getUrl(), FILTER_HMAC_PERMS+"["+hmacRule.getNeedPerms()+"]");
            	} else {
            		dynamicRules.putIfAbsent(hmacRule.getUrl(), FILTER_HMAC);
            	}
    		}
		}
		if(null!=jwtRules&&!jwtRules.isEmpty()){
            for(JwtRule jwtRule : jwtRules){
            	if(Strings.isNullOrEmpty(jwtRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(jwtRule.getNeedRoles())){
            		dynamicRules.putIfAbsent(jwtRule.getUrl(), FILTER_JWT_ROLES+"["+jwtRule.getNeedRoles()+"]");
            	} else if(Strings.isNullOrEmpty(jwtRule.getNeedPerms())){
            		dynamicRules.putIfAbsent(jwtRule.getUrl(), FILTER_JWT_PERMS+"["+jwtRule.getNeedPerms()+"]");
            	} else {
            		dynamicRules.putIfAbsent(jwtRule.getUrl(), FILTER_JWT);
            	}
    		}
		}
		if(null!=customRules&&!customRules.isEmpty()){
            for(CustomRule customRule : customRules){
            	if(Strings.isNullOrEmpty(customRule.getUrl())) continue;
            	if(Strings.isNullOrEmpty(customRule.getRule())) continue;
            	dynamicRules.putIfAbsent(customRule.getUrl(), customRule.getRule());
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