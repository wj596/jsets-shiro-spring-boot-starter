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
package org.jsets.shiro.service;

import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
/**
 * 安全信息服务，应用系统必须实现这个接口，为安全认证提供必要的信息。
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */ 
public interface ShiroStatelessAccountProvider {
	/**
	 * 根据客户标识检查账号
	 * <br>如果账号有异常或者不允许方法可抛出AuthenticationException或返回false
	 * @param appId 客户标识
	 * @return 账号信息
	 * @see org.jsets.weblite.core.security.Account
	 */
	public String loadAppKey(String appId) throws AuthenticationException;
	/**
	 * 根据客户标识加载持有角色
	 * @param appId 客户标识
	 * @return 角色列表
	 */
	public Set<String> loadRoles(String appId);
	/**
	 * 根据客户标识加载持有权限
	 * @param appId 客户标识
	 * @return 角色列表
	 */
	public Set<String> loadPermissions(String appId);	
}