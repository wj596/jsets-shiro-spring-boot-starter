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
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessAccount;
import org.jsets.shiro.service.ShiroCryptoService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

/**
 * JWT匹配器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsJwtMatcher implements CredentialsMatcher {
	
	private final ShiroProperties shiroProperties;
	private final ShiroCryptoService cryptoService;

	public JsetsJwtMatcher(ShiroProperties shiroProperties,ShiroCryptoService cryptoService){
		this.shiroProperties = shiroProperties;
		this.cryptoService = cryptoService;
	}
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		String jwt = (String) info.getCredentials();
		StatelessAccount statelessAccount = null;
		try{
			statelessAccount = this.cryptoService.parseJwt(jwt);
		} catch(SignatureException e){
			throw new AuthenticationException(shiroProperties.getJwtSecretKey());
		} catch(ExpiredJwtException e){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtTimeout());
		} catch(Exception e){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtError());
		}
		if(null == statelessAccount){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtError());
		}
		// 可以做签发方验证
		// 可以做接收方验证
        return true;
	}

}