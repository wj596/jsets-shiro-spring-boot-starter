package org.jsets.shiro.config;

import org.jsets.shiro.service.DefaultShiroAccountProviderImpl;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.ShiroCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnMissingBean(JsetsShiroConfiguration.class)
public class DefaultShiroConfiguration extends JsetsShiroConfiguration{

	@Autowired
	private ShiroCryptoService shiroCryptoService;
	
	@Override
	protected void configure(SecurityManagerConfig securityManager) {
		ShiroAccountProvider accountProvider 
							= new DefaultShiroAccountProviderImpl(this.shiroCryptoService);
		securityManager.setAccountProvider(accountProvider);
		
	}

	@Override
	protected void configure(FilterChainConfig filterChain) {

	}

}