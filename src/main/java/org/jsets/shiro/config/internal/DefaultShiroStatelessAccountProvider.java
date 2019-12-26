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
package org.jsets.shiro.config.internal;

import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.jsets.shiro.api.ShiroAccountProvider;
import org.jsets.shiro.api.ShiroStatelessAccountProvider;
import org.jsets.shiro.model.Account;

/**
 * 默认无状态账号提供者实现
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class DefaultShiroStatelessAccountProvider implements ShiroStatelessAccountProvider{
	
	private final ShiroAccountProvider shiroAccountProvider;
	
	public DefaultShiroStatelessAccountProvider(ShiroAccountProvider shiroAccountProvider) {
		this.shiroAccountProvider = shiroAccountProvider;
	}
	
	@Override
	public boolean checkAccount(String appId) throws AuthenticationException {
		Account account = this.shiroAccountProvider.loadAccount(appId);
		if(null == account) return false;
		return true;
	}
	
	@Override
	public String loadAppKey(String appId) throws AuthenticationException {
		return null;
	}

	@Override
	public Set<String> loadRoles(String appId) {
		return this.shiroAccountProvider.loadRoles(appId);
	}

	@Override
	public Set<String> loadPermissions(String appId) {
		return this.shiroAccountProvider.loadPermissions(appId);
	}
}