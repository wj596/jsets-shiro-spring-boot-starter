package org.jsets.shiro.service;

import java.util.Arrays;
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.DefaultAccount;
import com.google.common.collect.Sets;

/**
 * 默认的账号服务
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */
public class DefaultShiroAccountProviderImpl implements ShiroAccountProvider {

	private final ShiroCryptoService shiroCryptoService;
	
	public DefaultShiroAccountProviderImpl(ShiroCryptoService shiroCryptoService){
		this.shiroCryptoService = shiroCryptoService;
	}
	
	protected static final String DEFAULT_ACCOUNT = "test";
	protected static final String DEFAULT_ROLES = "testRole";
	protected static final String DEFAULT_PERMS = "testPerm";

	@Override
	public Account loadAccount(String account) throws AuthenticationException {
		if(!DEFAULT_ACCOUNT.equals(account)) throw new AuthenticationException("用户名或密码错误");
		return new DefaultAccount(account,this.shiroCryptoService.password(DEFAULT_ACCOUNT));
	}

	@Override
	public Set<String> loadRoles(String account) {
		return Sets.newHashSet(Arrays.asList(DEFAULT_ROLES));
	}

	@Override
	public Set<String> loadPermissions(String account) {
		return Sets.newHashSet(Arrays.asList(DEFAULT_PERMS));
	}
}