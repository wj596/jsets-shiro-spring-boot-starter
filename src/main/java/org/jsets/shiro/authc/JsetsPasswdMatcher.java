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
import org.jsets.shiro.config.JsetsShiroManager;
import org.jsets.shiro.config.MessageConfig;
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

	private  ShiroProperties properties;
	private  MessageConfig messages;
	private  PasswdRetryLimitHandler passwdRetryLimitHandler;
	private  CacheDelegator cacheDelegator;
	private  ShiroCryptoService cryptoService;
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		String credentials = String.valueOf((char[]) token.getCredentials());
		String account = (String) info.getPrincipals().getPrimaryPrincipal();
		String password = (String) info.getCredentials();
		String encrypted  = this.cryptoService.password(credentials);
		if (!password.equals(encrypted)) {
			int passwdMaxRetries = this.properties.getPasswdMaxRetries();
			String errorMsg = this.messages.getMsgAccountPasswordError();
			if (passwdMaxRetries > 0 && null != this.passwdRetryLimitHandler) {
				errorMsg = this.messages.getMsgPasswordRetryError();
				int passwdRetries = this.cacheDelegator.incPasswdRetryCount(account);
				if (passwdRetries >= passwdMaxRetries-1) {
					this.passwdRetryLimitHandler.handle(account);
				}
				int remain = passwdMaxRetries - passwdRetries;
				errorMsg = errorMsg.replace("{total}", String.valueOf(passwdMaxRetries))
								   .replace("{remain}", String.valueOf(remain));
			}
			throw new AuthenticationException(errorMsg);
		}
		this.cacheDelegator.cleanPasswdRetryCount(account);
		return true;
	}

	public void setProperties(ShiroProperties properties) {
		this.properties = properties;
	}
	public void setCacheDelegator(CacheDelegator cacheDelegator) {
		this.cacheDelegator = cacheDelegator;
	}
	public void setCryptoService(ShiroCryptoService cryptoService) {
		this.cryptoService = cryptoService;
	}
	public void setMessages(MessageConfig messages) {
		this.messages = messages;
	}
	public void setPasswdRetryLimitHandler(PasswdRetryLimitHandler passwdRetryLimitHandler) {
		this.passwdRetryLimitHandler = passwdRetryLimitHandler;
	}
	
}