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
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.api.ShiroStatelessAccountProvider;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessAccount;
import org.jsets.shiro.token.HmacToken;
import org.jsets.shiro.util.CommonUtils;
import org.jsets.shiro.util.ShiroUtils;
import com.google.common.base.Strings;
import io.jsonwebtoken.lang.Collections;

/**
 * 基于HMAC（ 散列消息认证码）的控制域
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class HmacRealm extends AuthorizingRealm {

	private final ShiroProperties properties;
	private final CacheDelegator cacheDelegator;
	private final ShiroStatelessAccountProvider accountProvider;

	public HmacRealm(ShiroProperties properties, CacheDelegator cacheDelegator,
			ShiroStatelessAccountProvider accountProvider) {
		this.properties = properties;
		this.cacheDelegator = cacheDelegator;
		this.accountProvider = accountProvider;
	}

	public Class<?> getAuthenticationTokenClass() {
		return HmacToken.class;
	}

	/**
	 * 认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		if (!(token instanceof HmacToken))
			return null;// 只认证HmacToken
		HmacToken hmacToken = (HmacToken) token;
		String appId = hmacToken.getAppId();
		String digest = hmacToken.getDigest();
		if (this.properties.isHmacBurnEnabled() && this.cacheDelegator.burnedToken(digest)) {
			throw new AuthenticationException(ShiroProperties.MSG_BURNED_TOKEN);
		}
		String secretKey = this.accountProvider.loadAppKey(appId);
		if (Strings.isNullOrEmpty(secretKey))
			secretKey = this.properties.getHmacSecretKey();
		if (Strings.isNullOrEmpty(secretKey))
			throw new AuthenticationException(ShiroProperties.MSG_NO_SECRET_KEY);
		Boolean match = Boolean.TRUE;
		String encrypted = ShiroUtils.hmacDigest(hmacToken.getBaseString(), secretKey);

		if (Strings.isNullOrEmpty(encrypted))
			throw new AuthenticationException(this.properties.getMsgHmacError());
		if (!Objects.equals(digest, encrypted)) {
			match = Boolean.FALSE;
			throw new AuthenticationException(this.properties.getMsgHmacError());
		}
		Long current = System.currentTimeMillis();
		Long timestamp = Long.valueOf(hmacToken.getTimestamp());
		// 数字签名超时失效
		if ((current - timestamp) > this.properties.getHmacPeriod())
			throw new AuthenticationException(this.properties.getMsgHmacTimeout());
		// 检查账号
		boolean check = this.accountProvider.checkAccount(appId);
		if (!check)
			throw new AuthenticationException(this.properties.getMsgAccountException());
		ShiroUtils.setStatelessAccount(StatelessAccount.of(hmacToken));

		return new SimpleAuthenticationInfo("hmac:{" + appId + "}", match, this.getName());
	}

	/**
	 * 授权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String payload = (String) principals.getPrimaryPrincipal();
		String appId = CommonUtils.hmacPayload(payload);
		if (Objects.isNull(appId))
			return null;
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		Set<String> roles = this.accountProvider.loadRoles(appId);
		Set<String> permissions = this.accountProvider.loadPermissions(appId);
		if (!Collections.isEmpty(roles))
			info.setRoles(roles);
		if (!Collections.isEmpty(permissions))
			info.setStringPermissions(permissions);
		return info;
	}
}