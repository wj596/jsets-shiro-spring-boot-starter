package org.jsets.shiro.service;

import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
/**
 * 安全信息服务，应用系统必须实现这个接口，为安全认证提供必要的信息。
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
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