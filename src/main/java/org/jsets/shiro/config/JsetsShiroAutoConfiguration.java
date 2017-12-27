package org.jsets.shiro.config;

import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroSecurityService;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * shiro配置
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
@Configuration
@Import(DefaultShiroConfiguration.class)
public class JsetsShiroAutoConfiguration {

	@Bean
	public BeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}
	
	@Bean
	public ShiroCryptoService shiroCryptoService() {
		return new ShiroCryptoService();
	}
	
	@Bean
	public ShiroSecurityService shiroSecurityService() {
		return new ShiroSecurityService(JsetsSecurityManager.getInstance());
	}
}