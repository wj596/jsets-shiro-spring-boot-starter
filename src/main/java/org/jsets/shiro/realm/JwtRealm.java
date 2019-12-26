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

import java.util.Map;
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
import org.jsets.shiro.token.JwtToken;
import org.jsets.shiro.util.CommonUtils;
import org.jsets.shiro.util.ShiroUtils;
import com.google.common.base.Strings;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.lang.Collections;

/**
 * 基于JWT（ JSON WEB TOKEN）的控制域
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JwtRealm extends AuthorizingRealm{

	private final ShiroProperties properties;
	private final CacheDelegator cacheDelegator;
	private final ShiroStatelessAccountProvider accountProvider;

	public JwtRealm(ShiroProperties properties
			,CacheDelegator cacheDelegator,ShiroStatelessAccountProvider accountProvider) {
		this.properties = properties;
		this.cacheDelegator = cacheDelegator;
		this.accountProvider = accountProvider;
	}
	
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;
	}
	
	/**
	 *  认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		if(!(token instanceof JwtToken)) return null;// 只认证JwtToken
		String jwt = ((JwtToken)token).getJwt();
		if (this.properties.isHmacBurnEnabled() && this.cacheDelegator.burnedToken(jwt)) {
			throw new AuthenticationException(ShiroProperties.MSG_BURNED_TOKEN);
		}
		String payload = null;
		Map<String,Object> jwtMap = null;
		try{
			 payload = CommonUtils.parseJwtPayload(jwt);
			 jwtMap = CommonUtils.readJSON(payload,Map.class);
		} catch(MalformedJwtException e){
			throw new AuthenticationException(this.properties.getMsgJwtMalformed());
		} catch(Exception e){
			throw new AuthenticationException(this.properties.getMsgJwtError());
		}
		if(Objects.isNull(payload))
			throw new AuthenticationException(this.properties.getMsgJwtError());
		String appId = (String)jwtMap.get("subject");
		String secretKey = this.accountProvider.loadAppKey(appId);
		if(Strings.isNullOrEmpty(secretKey)) secretKey = this.properties.getJwtSecretKey();
		if(Strings.isNullOrEmpty(secretKey)) 
			throw new AuthenticationException(ShiroProperties.MSG_NO_SECRET_KEY);
		Boolean match = Boolean.TRUE;
		StatelessAccount statelessAccount = null;
		try{
			statelessAccount = ShiroUtils.parseJwt(jwt, secretKey);
		} catch(SignatureException e){
			throw new AuthenticationException(this.properties.getMsgJwtSignature());
		} catch(ExpiredJwtException e){
			throw new AuthenticationException(this.properties.getMsgJwtTimeout());
		} catch(Exception e){
			throw new AuthenticationException(this.properties.getMsgJwtError());
		}
		if(Objects.isNull(statelessAccount)) {
			match = Boolean.FALSE;
			throw new AuthenticationException(this.properties.getMsgJwtError());
		}
		
		return new SimpleAuthenticationInfo("jwt:"+payload,match,this.getName());
	}
	
	/** 
     * 授权 
     */  
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		String payload = (String) principals.getPrimaryPrincipal();
		String jwtPayload = CommonUtils.jwtPayload(payload);
		if(Objects.isNull(jwtPayload)) return null;
        Map<String, Object> payloadMap = CommonUtils.readJSON(jwtPayload,Map.class);
    	Set<String> roles = CommonUtils.split((String)payloadMap.get("roles"));
    	Set<String> permissions = CommonUtils.split((String)payloadMap.get("perms"));
    	SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();
		if(!Collections.isEmpty(roles)) info.setRoles(roles);
		if(!Collections.isEmpty(permissions)) info.setStringPermissions(permissions);
		return info;
	}
}