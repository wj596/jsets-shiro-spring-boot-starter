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


import java.util.Map;
import javax.servlet.Filter;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import com.google.common.collect.Maps;

/**
 * shiro 过滤器链配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class FilterChainConfig{
	
	private final Map<String, Filter> filters = Maps.newLinkedHashMap();
	private ShiroFilteRulesProvider shiroFilteRulesProvider;

	protected FilterChainConfig(){};
	
	/**
	 *  设置过滤规则提供者，实现动态URL鉴权过滤
	 *  
	 *  @param shiroFilteRulesProvider 
	 *  @see org.jsets.shiro.service.ShiroFilteRulesProvider
	 */
	public void setShiroFilteRulesProvider(ShiroFilteRulesProvider shiroFilteRulesProvider) {
		this.shiroFilteRulesProvider = shiroFilteRulesProvider;
	}
	/**
	 *  添加鉴权过滤
	 * <br>组件中提供的过滤器：
	 * <br>authc:基于表单的登陆过滤器
	 * <br>roles:基于角色的验证过滤器
	 * <br>perms:基于权限的验证过滤器
	 * <br>user:断言seesion中存在用户的过滤器
	 * <br>keepOne:账号唯一用户登陆过滤器
	 * <br>forceLogout:强制用户下线过滤器
	 * <br>hmac:hmac数字签名认证过滤器
	 * <br>hmacRoles:hmac数字签名角色验证过滤器
	 * <br>hmacPerms:hmac数字签名权限验证过滤器
	 * <br>jwt:jwt令牌认证过滤器
	 * <br>jwtRoles:jwt令牌角色验证过滤器
	 * <br>jwtPerms:jwt令牌权限验证过滤器
	 * <br>如果无法满足需求，可设置此项覆盖或者添加过滤器
	 */
	public void addFilter(String name,Filter filter) {
		this.filters.put(name, filter);
	}
	public ShiroFilteRulesProvider getShiroFilteRulesProvider() {
		return shiroFilteRulesProvider;
	}
	public Map<String, Filter> getFilters() {
		return filters;
	}
}