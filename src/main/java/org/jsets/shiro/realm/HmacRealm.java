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

import java.util.Date;
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessAccount;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.jsets.shiro.token.HmacToken;

/**
 * 基于HMAC（ 散列消息认证码）的控制域
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class HmacRealm extends AuthorizingRealm{
	
	private final ShiroCryptoService cryptoService;
	private final ShiroStatelessAccountProvider accountProvider;

	public HmacRealm(ShiroCryptoService cryptoService,ShiroStatelessAccountProvider accountProvider){
		this.cryptoService = cryptoService;
		this.accountProvider = accountProvider;
	}
	
	public Class<?> getAuthenticationTokenClass() {
		return HmacToken.class;
	}
	
	/**
	 *  认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("hmac 认证");
		HmacToken hmacToken = (HmacToken)token;
		String appId = hmacToken.getAppId();
		// 此处可以查询数据 检是否存在该账号、查该账号是否被锁定、该账号是否被禁用
		Long now = System.currentTimeMillis();
		Long tokenTimestamp = Long.valueOf(hmacToken.getTimestamp());
		// 十分钟之前的时间戳
		//if ((now-tokenTimestamp) > 600000) {
		//	throw new AuthenticationException(Constants.HMAC_AUTHC_ERROR_MSG);
		//}
		// 服务端生成的摘要
		String serverDigest = cryptoService.hmacDigest(hmacToken.getBaseString()
												,this.accountProvider.loadAppKey(appId));
		if(!serverDigest.equals(hmacToken.getDigest())){
			throw new AuthenticationException(ShiroProperties.MSG_HMAC_AUTHC_ERROR);
		}
		StatelessAccount statelessAccount = new StatelessAccount();
		statelessAccount.setTokenId(hmacToken.getDigest());
		statelessAccount.setAppId(hmacToken.getAppId());
		statelessAccount.setHost(hmacToken.getHost());
		statelessAccount.setIssuedAt(new Date(tokenTimestamp));
		StatelessThreadContext.setAccount(statelessAccount);
        return new SimpleAuthenticationInfo(statelessAccount,Boolean.TRUE,getName());
	}
	
	/** 
     * 授权 
     */  
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		Object principal = principals.getPrimaryPrincipal();
		if(!(principal instanceof StatelessAccount)) return null;
		SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();
		StatelessAccount statelessPrincipal = (StatelessAccount)principal;
		Set<String> roles = this.accountProvider.loadRoles(statelessPrincipal.getAppId());
		Set<String> permissions = this.accountProvider.loadPermissions(statelessPrincipal.getAppId());
		if(null!=roles&&!roles.isEmpty())
			info.setRoles(roles);
		if(null!=permissions&&!permissions.isEmpty())
			info.setStringPermissions(permissions);
        return info;  
	}
}