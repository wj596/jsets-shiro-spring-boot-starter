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

import javax.annotation.PostConstruct;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
/**
 * Shiro应用端定制适配器，用户可以继承此类以设置自己的配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
@AutoConfigureAfter(JsetsShiroAutoConfiguration.class)
public abstract class JsetsShiroConfigurationAdapter {

	@Autowired
	private JsetsShiroManager shiroManager;
	
	@PostConstruct
	private void init(){
		this.configure(this.shiroManager.getManagerConfig());
		this.configure(this.shiroManager.getFilterConfig());
		this.shiroManager.build();
	}

	/**
	 *   设置、定制安全组件
	 *  <br>主要方法：
	 * 	<br>securityManager.setAccountProvider(accountProvider) 设置账号信息提供者
	 *	<br>securityManager.setPasswdRetryLimitHandler(passwdRetryLimitHandler) 设置密码连续错误超限处理器
	 *  <br>其他方法@see org.jsets.shiro.config.SecurityManagerConfig
	 *  <br>
	 */
	protected abstract void configure(SecurityManagerConfig securityManager);
	/**
	 *   设置、定制过滤器链
	 *  <br>主要方法：
	 * 	<br>filterChainConfig.setShiroFilteRulesProvider(shiroFilteRulesProvider) 设置动态过滤规则提供者
	 *  <br>其他方法@see org.jsets.shiro.config.FilterChainConfig
	 *  <br>
	 */
	protected abstract void configure(FilterChainConfig filterChain);
	
	
	@Bean
	public ShiroFilterFactoryBean shiroFilterFactoryBean() {
		return this.shiroManager.getShiroFilterFactoryBean();
	}

}