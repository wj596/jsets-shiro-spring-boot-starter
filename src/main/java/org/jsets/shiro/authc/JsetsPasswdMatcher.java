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
package org.jsets.shiro.authc;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.handler.PasswdRetryLimitHandler;
import org.jsets.shiro.service.ShiroCryptoService;

/**
 * 密码匹配器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsPasswdMatcher implements CredentialsMatcher {

	private final ShiroProperties shiroProperties;
	private final CacheDelegator cacheDelegator;
	private final ShiroCryptoService cryptoService;
	private final PasswdRetryLimitHandler retryLimitHandler;
	
	
	public JsetsPasswdMatcher(ShiroProperties shiroProperties,CacheDelegator cacheDelegator
				,ShiroCryptoService cryptoService,PasswdRetryLimitHandler retryLimitHandler){
		this.shiroProperties = shiroProperties;
		this.cacheDelegator = cacheDelegator;
		this.cryptoService = cryptoService;
		this.retryLimitHandler = retryLimitHandler;
	}
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		String credentials = String.valueOf((char[]) token.getCredentials());
		String account = (String) info.getPrincipals().getPrimaryPrincipal();
		String password = (String) info.getCredentials();
		String encrypted  = this.cryptoService.password(credentials);
		if (!password.equals(encrypted)) {
			int passwdMaxRetries = this.shiroProperties.getPasswdMaxRetries();
			String errorMsg = "用户名或密码错误";
			if (passwdMaxRetries > 0 && null != this.retryLimitHandler) {
				int passwdRetries = this.cacheDelegator.incPasswdRetryCount(account);
				if (passwdRetries >= passwdMaxRetries-1) {
					this.retryLimitHandler.handle(account);
				}
				errorMsg = "密码错误,您还可以重试 " + (passwdMaxRetries - passwdRetries) + " 次";
			}
			throw new AuthenticationException(errorMsg);
		}
		this.cacheDelegator.cleanPasswdRetryCount(account);
		return true;
	}

}