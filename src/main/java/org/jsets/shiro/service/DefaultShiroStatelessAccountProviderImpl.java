package org.jsets.shiro.service;

import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;

/**
 * 
 * @author wangjie
 *
 */
public class DefaultShiroStatelessAccountProviderImpl implements ShiroStatelessAccountProvider{
	
	private final ShiroAccountProvider shiroSecurityService;
	
	public DefaultShiroStatelessAccountProviderImpl(ShiroAccountProvider shiroSecurityService){
		this.shiroSecurityService = shiroSecurityService;
	}
	
	@Override
	public Set<String> loadRoles(String appId) {
		return this.shiroSecurityService.loadRoles(appId);
	}

	@Override
	public Set<String> loadPermissions(String appId) {
		return this.shiroSecurityService.loadPermissions(appId);
	}
	@Override
	public String loadAppKey(String appId) throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}
	
}