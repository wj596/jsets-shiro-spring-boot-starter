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

import org.jsets.shiro.service.DefaultAccountProvider;
import org.jsets.shiro.service.ShiroCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
/**
 * 默认配置
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Configuration
@ConditionalOnMissingBean(JsetsShiroConfigurationAdapter.class)
public class DefaultShiroConfiguration extends JsetsShiroConfigurationAdapter{

	@Autowired
	private ShiroCryptoService shiroCryptoService;
	
	@Override
	protected void configure(SecurityManagerConfig securityManager) {
		System.out.println("欢迎使用： jsets-shiro-spring-boot-starter");
		System.out.println("已为您创建体验账号： test,密码test");
		DefaultAccountProvider defAccountProvider = new DefaultAccountProvider();
		defAccountProvider.setShiroCryptoService(shiroCryptoService);
		securityManager.setAccountProvider(defAccountProvider);
	}

	@Override
	protected void configure(FilterChainConfig filterChain) {
		
	}

}