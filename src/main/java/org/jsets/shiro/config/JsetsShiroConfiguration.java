package org.jsets.shiro.config;

import javax.annotation.PostConstruct;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.authc.JsetsModularRealmAuthenticator;
import org.jsets.shiro.authc.JsetsSubjectFactory;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.service.ShiroCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * ShiroConfiguration定制适配器，用户可以继承此类以定制自己的shiro
 * 
 * @author wangjie
 *
 */
@EnableConfigurationProperties(ShiroProperties.class)
@AutoConfigureAfter(JsetsShiroAutoConfiguration.class)
public abstract class JsetsShiroConfiguration {

	private final JsetsSecurityManager jsetsSecurityManager = JsetsSecurityManager.getInstance();
	
	@PostConstruct
	private void init(){
		SecurityManagerConfig securityManagerConfig = new SecurityManagerConfig();
		FilterChainConfig filterChainConfig = new FilterChainConfig();
		this.configure(securityManagerConfig);
		this.configure(filterChainConfig);
		
		this.jsetsSecurityManager.setSecurityConfig(securityManagerConfig);
		this.jsetsSecurityManager.setFilterChainConfig(filterChainConfig);
	}

	/**
	 *   安全管理器设置
	 *  <br>主要方法：
	 * 	<br>securityManager.setAccountProvider(accountProvider) 设置账号信息提供者
	 *	<br>securityManager.setPasswdRetryLimitHandler(passwdRetryLimitHandler) 设置密码连续错误超限处理器
	 *  <br>其他方法见使用说明文档
	 *  <br>
	 */
	protected abstract void configure(SecurityManagerConfig securityManager);
	/**
	 *   过滤器链设置
	 *  <br>主要方法：
	 * 	<br>filterChainConfig.setShiroFilteRulesProvider(shiroFilteRulesProvider) 设置动态过滤规则提供者
	 *  <br>其他方法见使用说明文档
	 *  <br>
	 */
	protected abstract void configure(FilterChainConfig filterChain);
	
	@Autowired
	private ShiroProperties properties;
	@Autowired(required=false)
	private RedisTemplate redisTemplate;
	
	@Bean
	public DefaultWebSessionManager sessionManager() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(this.properties.getSessionTimeout());
		sessionManager.setSessionIdUrlRewritingEnabled(Boolean.FALSE);
		this.jsetsSecurityManager.setSessionManager(sessionManager);
		this.jsetsSecurityManager.decideSessionDAO();
		this.jsetsSecurityManager.decideSessionListeners();
		sessionManager.setSessionValidationInterval(1000000);
		return sessionManager;
	}
	
	@Bean
	public CookieRememberMeManager rememberMeManager() {
		CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
		rememberMeManager.setCipherKey(CodecSupport.toBytes(this.properties.getRemembermeSecretKey()));
		this.jsetsSecurityManager.decideRememberMeCookie(this.properties,rememberMeManager);
		return rememberMeManager;
	}
	
	@Bean
	public CacheDelegator cacheDelegator() {
		CacheDelegator cacheDelegator = new CacheDelegator();
		CacheManager cacheManager = 
				this.jsetsSecurityManager.decideCacheManager(this.properties, redisTemplate);
		cacheDelegator.setCacheManager(cacheManager);
		this.jsetsSecurityManager.setCacheDelegator(cacheDelegator);
		return cacheDelegator;
	}

	@Bean
	public DefaultWebSecurityManager securityManager(DefaultWebSessionManager sessionManager
													,CookieRememberMeManager rememberMeManager
													,CacheDelegator cacheDelegator
													,ShiroCryptoService cryptoService){
		
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setSessionManager(sessionManager);
		securityManager.setRememberMeManager(rememberMeManager);
		securityManager.setAuthenticator(new JsetsModularRealmAuthenticator());
		DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) securityManager.getSubjectDAO();
		DefaultSessionStorageEvaluator storageEvaluator = 
					(DefaultSessionStorageEvaluator)subjectDAO.getSessionStorageEvaluator();
		JsetsSubjectFactory subjectFactory = new JsetsSubjectFactory(storageEvaluator);
		securityManager.setSubjectFactory(subjectFactory);
		CacheManager cacheManager = 
				this.jsetsSecurityManager.decideCacheManager(this.properties, redisTemplate);
		securityManager.setCacheManager(cacheManager);
		this.jsetsSecurityManager.decideRealms(this.properties,securityManager,cryptoService,cacheDelegator);
		SecurityUtils.setSecurityManager(securityManager);
		return securityManager;
	}
	
	@Bean
	public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager
								,DefaultWebSessionManager sessionManager,CacheDelegator cacheDelegator) {
		
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		this.jsetsSecurityManager.setShiroFilterFactoryBean(shiroFilterFactoryBean);
		this.jsetsSecurityManager.decideFixations(properties);
		this.jsetsSecurityManager.decideFilters(this.properties);
		this.jsetsSecurityManager.decideFilteRules(this.properties);
		return shiroFilterFactoryBean;
	}
}