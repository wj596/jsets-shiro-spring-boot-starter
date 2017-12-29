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

import java.util.Date;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessAccount;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.jsets.shiro.token.HmacToken;

/**
 * HMAC签名匹配器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsHmacMatcher implements CredentialsMatcher {

	private final ShiroProperties shiroProperties;
	private final ShiroCryptoService cryptoService;
	private final ShiroStatelessAccountProvider accountProvider;

	public JsetsHmacMatcher(ShiroProperties shiroProperties
			,ShiroCryptoService cryptoService,ShiroStatelessAccountProvider accountProvider){
		this.shiroProperties = shiroProperties;
		this.cryptoService = cryptoService;
		this.accountProvider = accountProvider;
	}
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		HmacToken hmacToken = (HmacToken)token;
		String appId = hmacToken.getAppId();
		String digest = (String) info.getCredentials();
		String serverDigest = cryptoService.hmacDigest(hmacToken.getBaseString(),this.accountProvider.loadAppKey(appId));
		if(!serverDigest.equals(digest)){
			throw new AuthenticationException(MessageConfig.instance().getMsgHmacError());
		}
		Long currentTimeMillis = System.currentTimeMillis();
		Long tokenTimestamp = Long.valueOf(hmacToken.getTimestamp());
		// 数字签名超时失效
		if ((currentTimeMillis-tokenTimestamp) > this.shiroProperties.getHmacPeriod()) {
			throw new AuthenticationException(MessageConfig.instance().getMsgHmacTimeout());
		}
		// 检查账号
		boolean checkAccount = this.accountProvider.checkAccount(appId);
		if(!checkAccount){
			throw new AuthenticationException(MessageConfig.instance().getMsgAccountExcept());
		}
		StatelessAccount statelessAccount = new StatelessAccount();
		statelessAccount.setTokenId(hmacToken.getDigest());
		statelessAccount.setAppId(hmacToken.getAppId());
		statelessAccount.setHost(hmacToken.getHost());
		statelessAccount.setIssuedAt(new Date(tokenTimestamp));
		StatelessLocal.setAccount(statelessAccount);
		return true;
	}

}