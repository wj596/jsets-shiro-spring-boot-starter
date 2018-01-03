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

import java.util.List;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.RolePermRule;

/**
 * 动态过滤规则提供者接口
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public interface ShiroFilteRulesProvider  {
	/**
	 * 加载基于角色/资源的过滤规则
	 * <br>大部分系统的安全体系都是RBAC(基于角色的权限访问控制)授权模型。
	 * <br>即：用户--角色--资源(URL),对应关系可配并且存储在数据库中。
	 * <br>此方法提供的数据为：RolePermRule{url资源地址、needRoles需要的角色列表}
	 * <br>在shiro中生成的过滤器链为：url=roles[角色1、角色2、角色n]
	 * <br>当用户持有[角色1、角色2、角色n]中的任何一个角色，则给予访问，否则不予访问
	 * 
	 * <br>权限指用户能操作资源的统称、角色则说权限的集合。
	 * <br>权限授权模型直接表示为：用户--资源(URL)。
	 * <br>此方法提供的数据格为：PermRule{url资源地址、needPerms需要的权限列表}
	 * <br>在shiro中生成的过滤器链为：url=perms[权限编码1、权限编码2、权限编码n]
	 * <br>当用户持有[权限编码1、权限编码2、权限编码n]中的任何一个权限，则给予访问，否则不予访问
	 * 
	 * @return  @see org.jsets.shiro.model.RolePermRule
	 *
	 */
	public List<RolePermRule> loadRolePermRules();

	/**
	 * 加载基于HMAC的过滤规则
	 * <br>HMAC：(散列消息认证码)是一种摘要形式的数字签名方法,通常用在无状态的认证授权中。
	 * <br>此方法提供的数据为：HmacRule{url资源地址、needRoles需要的角色列表、needPerms需要的权限列表}
	 * <br>只需要身份认证不需要角色验证needRoles为空、只需要身份认证不需要权限验证needPerms为空
	 * <br>在shiro中生成的过滤器链为：url=hmac、url=hmacRoles[needRoles]、url=hmacPerms[needPerms]
	 * @return @see org.jsets.shiro.model.RolePermRule
	 */
	public List<RolePermRule> loadHmacRules();
	/**
	 * 加载基于JWT的过滤规则
	 * <br>JWT：(JSON WEB TOKEN)是一种开放标准的令牌规范,通常用在无状态的认证授权中。
	 * <br>此方法提供的数据为：JwtRule{url资源地址、needRoles需要的角色列表、needPerms需要的权限列表}
	 * <br>只需要身份认证不需要角色验证needRoles为空、只需要身份认证不需要权限验证needPerms为空
	 * <br>在shiro中生成的过滤器链为：url=jwt、url=jwtRoles[needRoles]、url=jwtPerms[needPerms]
	 * @return @see org.jsets.shiro.model.RolePermRule
	 */
	public List<RolePermRule> loadJwtRules();
	/**
	 * 加载自定义的过滤规则
	 * <br>此方法提供的数据为：JwtRule{url资源地址、rule过滤规则}
	 * <br>比如您自定义了一个IP白名单过滤器，过滤器的名称为ipWhiteList
	 * <br>则可以设置url=资源地址,rule=ipWhiteList
	 * @return @see org.jsets.shiro.model.CustomRule
	 */
	public List<CustomRule> loadCustomRules();
	
}
