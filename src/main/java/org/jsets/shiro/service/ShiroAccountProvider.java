package org.jsets.shiro.service;

import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.jsets.shiro.model.Account;
/**
 * 账号信息提供者接口<br>
 * 应用系统实现这个接口为鉴权提供必要的账号信息。
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */ 
public interface ShiroAccountProvider {
	/**
	 * 根据用户名获取账号信息
	 * @return 账号信如果查找不到用户返回null
	 * @param userId息
	 * @see org.jsets.weblite.core.security.Account
	 */
	public Account loadAccount(String account) throws AuthenticationException;
	/**
	 * 根据用户名称加载用户所有的角色
	 * @param userId 账号
	 * @return 角色列表
	 */
	public Set<String> loadRoles(String account);
	/**
	 * 根据用户名称加载用户所有的权限
	 * @param userId 账号
	 * @return 权限列表
	 */
	public Set<String> loadPermissions(String account);
}