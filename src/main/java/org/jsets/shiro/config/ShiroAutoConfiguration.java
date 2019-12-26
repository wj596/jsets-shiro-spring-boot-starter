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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.jsets.shiro.api.ShiroCustomizer;
import org.jsets.shiro.session.JsetsModularRealmAuthenticator;
import org.jsets.shiro.session.JsetsSubjectFactory;
import org.jsets.shiro.util.SpringContextUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.shiro.mgt.SecurityManager;

/**
 * shiro自动配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Configuration
@ConditionalOnClass({DefaultWebSecurityManager.class, ShiroFilterFactoryBean.class})
@EnableConfigurationProperties(ShiroProperties.class) 
public class ShiroAutoConfiguration implements ApplicationContextAware{
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		SpringContextUtils.setApplicationContext(applicationContext);
	}
	
	@Bean
	public BeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}
	
	@Bean
	public SpringContextUtils springContextUtils() {
		return new SpringContextUtils();
	}

	@Bean
	public ShiroConfig shiroConfig(ShiroProperties properties
			,ObjectProvider<ShiroCustomizer> shiroCustomizerPvd
			,ObjectProvider<org.springframework.cache.CacheManager> springCacheManagerPvd) {
		ShiroConfig shiroConfig = new ShiroConfig();
		shiroConfig.setProperties(properties);
		shiroConfig.setCustomizer(shiroCustomizerPvd.getIfAvailable());
		shiroConfig.setSpringCacheManager(springCacheManagerPvd.getIfAvailable());
		shiroConfig.afterPropertiesSet();
		return shiroConfig;
	}
	
	@Bean
	public SecurityManager securityManager(ShiroConfig shiroConfig){

		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setSessionManager(shiroConfig.getSessionManager());
		securityManager.setRememberMeManager(shiroConfig.getRememberMeManager());
		securityManager.setAuthenticator(new JsetsModularRealmAuthenticator());
		DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) securityManager.getSubjectDAO();
		DefaultSessionStorageEvaluator storageEvaluator = 
					(DefaultSessionStorageEvaluator)subjectDAO.getSessionStorageEvaluator();
		JsetsSubjectFactory subjectFactory = new JsetsSubjectFactory(storageEvaluator);
		securityManager.setSubjectFactory(subjectFactory);
		securityManager.setCacheManager(shiroConfig.getCacheManager());
		securityManager.setRealms(shiroConfig.getRealms());
		SecurityUtils.setSecurityManager(securityManager);
		return securityManager;
	}
	
	@Bean
	public ShiroFilterFactoryBean shiroFilterFactoryBean(ShiroProperties properties,ShiroConfig shiroConfig,SecurityManager securityManager) {
		
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setLoginUrl(properties.getLoginUrl());
		shiroFilterFactoryBean.setSuccessUrl(properties.getLoginSuccessUrl());
		shiroFilterFactoryBean.setUnauthorizedUrl(properties.getUnauthorizedUrl());
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		shiroFilterFactoryBean.setFilters(shiroConfig.getFilters());
		shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroConfig.getRules());
		return shiroFilterFactoryBean;
	}
}