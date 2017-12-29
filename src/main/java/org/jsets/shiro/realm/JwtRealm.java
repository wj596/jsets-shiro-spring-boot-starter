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
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.token.JwtToken;
import org.jsets.shiro.util.Commons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.MalformedJwtException;
/**
 * 基于JWT（ JSON WEB TOKEN）的控制域
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JwtRealm extends AuthorizingRealm{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtRealm.class);
	
	private final ShiroProperties shiroProperties;
	
	public JwtRealm(ShiroProperties shiroProperties){
		this.shiroProperties = shiroProperties;
	}
	
	public Class<?> getAuthenticationTokenClass() {
		return JwtToken.class;
	}
	
	/**
	 *  认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		LOGGER.info("JWT 认证开始");
		// 只认证JwtToken
		if(!(token instanceof JwtToken)) return null;
		String jwt = ((JwtToken)token).getJwt();
		String payload = null;
		try{
			// 预先解析Payload
			// 没有做任何的签名校验
			 payload = Commons.parseJwtPayload(jwt);
		} catch(MalformedJwtException e){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtMalformed());
		} catch(Exception e){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtError());
		}
		if(null == payload){
			throw new AuthenticationException(MessageConfig.instance().getMsgJwtError());
		}
		return new SimpleAuthenticationInfo("jwt:"+payload,jwt,this.getName());
	}
	
	/** 
     * 授权 
     */  
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		LOGGER.info("JWT 授权开始");
		String payload = (String) principals.getPrimaryPrincipal();
		// likely to be json, parse it:
		if (payload.startsWith("jwt:") && payload.charAt(4) == '{' 
									   && payload.charAt(payload.length() - 1) == '}') { 
			
            Map<String, Object> payloadMap = Commons.readValue(payload.substring(4));
    		Set<String> roles = Commons.split((String)payloadMap.get("roles"));
    		Set<String> permissions = Commons.split((String)payloadMap.get("perms"));
    		SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();
    		if(null!=roles&&!roles.isEmpty())
    			info.setRoles(roles);
    		if(null!=permissions&&!permissions.isEmpty())
    			info.setStringPermissions(permissions);
    		 return info;
        }
        return null;
	}
}