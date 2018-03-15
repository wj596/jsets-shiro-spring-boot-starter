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

import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroSecurityService;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.AbstractCachingConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
/**
 * shiro自动配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Configuration
@EnableConfigurationProperties(ShiroProperties.class)
@Import(DefaultShiroConfiguration.class)
@AutoConfigureAfter(AbstractCachingConfiguration.class)
public class JsetsShiroAutoConfiguration {

	@Autowired
	private BeanFactory beanFactory;
	@Autowired
	private ShiroProperties properties;

	@Bean
	public BeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}
	
	@Bean
	public ShiroCryptoService shiroCryptoService() {
		return new ShiroCryptoService();
	}
	
	@Bean
	public JsetsShiroManager jsetsShiroManager(ShiroCryptoService shiroCryptoService) {
		JsetsShiroManager shiroManager = new JsetsShiroManager(
										 this.beanFactory
										,this.properties
										,new SecurityManagerConfig()
										,new FilterChainConfig());
		shiroManager.setCryptoService(shiroCryptoService);
		return shiroManager;
	}
	
	@Bean
	public ShiroSecurityService shiroSecurityService() {
		return new ShiroSecurityService();
	}
}