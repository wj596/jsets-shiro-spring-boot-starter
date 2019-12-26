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
package org.jsets.shiro.realm;

import java.util.Objects;
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.api.ShiroAccountProvider;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.listener.PasswdRetryLimitListener;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.util.CommonUtils;
import org.jsets.shiro.util.ShiroUtils;
import com.google.common.base.Strings;
import io.jsonwebtoken.lang.Collections;

/**
 * 基于用户、名密码的控制域
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class UsernamePasswordRealm extends AuthorizingRealm {
	
	private final ShiroProperties properties;
	private final CacheDelegator cacheDelegator;
	private final ShiroAccountProvider accountProvider;
	private final PasswdRetryLimitListener limitListener;

	public UsernamePasswordRealm(ShiroProperties properties,CacheDelegator cacheDelegator
			,ShiroAccountProvider accountProvider,PasswdRetryLimitListener limitListener) {
		this.properties = properties;
		this.cacheDelegator = cacheDelegator;
		this.accountProvider = accountProvider;
		this.limitListener = limitListener;
	}
	
	public Class<?> getAuthenticationTokenClass() {
		return UsernamePasswordToken.class;
	}
	
	/**
	 * 认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		if (!(token instanceof UsernamePasswordToken)) return null;// 只认证UsernamePasswordToken
		if(Objects.isNull(token.getPrincipal())||Objects.isNull(token.getCredentials()))
			throw new AuthenticationException(this.properties.getMsgAccountPasswordEmpty());
		String account = (String) token.getPrincipal();
		String password = String.valueOf((char[]) token.getCredentials());
		String encrypted = ShiroUtils.password(password);
		Account accountEntity = this.accountProvider.loadAccount(account);
		if (Objects.isNull(accountEntity)) {
			throw new AuthenticationException(this.properties.getMsgAccountNotExist());
		}
		Boolean match = Boolean.TRUE;
		if (!Objects.equals(encrypted, accountEntity.getPassword())) {
			match = Boolean.FALSE;
			if(this.isRetryLimit()) {
				int max = this.properties.getPasswdMaxRetries();
				int retries = this.cacheDelegator.incPasswdRetryCount(account);
				if (retries >= max) {
					this.limitListener.handle(account,max,retries);
				}
				String msg = this.properties.getMsgPasswordRetryError();
				msg = msg.replace("{total}",String.valueOf(max))
						 .replace("{remain}",String.valueOf(max-retries));
				throw new AuthenticationException(msg);
			} else 
				throw new AuthenticationException(this.properties.getMsgAccountPasswordError());
		}
		if(this.isRetryLimit()) 
			this.cacheDelegator.cleanPasswdRetryCount(account);
		
		return new SimpleAuthenticationInfo(account,match, getName());
	}

	/**
	 * 授权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		String account = (String) principals.getPrimaryPrincipal();
		if(Objects.isNull(account)||!Strings.isNullOrEmpty(CommonUtils.jwtPayload(account))
								  ||!Strings.isNullOrEmpty(CommonUtils.hmacPayload(account))) 
			return null;
		SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();
		Set<String> roles = this.accountProvider.loadRoles(account);
		Set<String> permissions = this.accountProvider.loadPermissions(account);
		if(!Collections.isEmpty(roles)) info.setRoles(roles);
		if(!Collections.isEmpty(permissions)) info.setStringPermissions(permissions);
        return info;  
	}
	
	private boolean isRetryLimit() {
		return this.properties.getPasswdMaxRetries() > 0 && null != this.limitListener;
	}
}