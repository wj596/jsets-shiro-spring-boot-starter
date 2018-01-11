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

import javax.xml.bind.DatatypeConverter;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessLogined;
import org.jsets.shiro.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Autowired;
import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * 
 * 签名\摘要服务
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class ShiroCryptoService {
	
	@Autowired
	private ShiroProperties shiroProperties;
	
	/**
	 * 生成密码
	 * @param plaintext 明文
	 */
	public String password(String plaintext) {
		return new SimpleHash(this.shiroProperties.getPasswdAlg()
							 ,plaintext
							 ,this.shiroProperties.getPasswdSalt()
							 ,this.shiroProperties.getPasswdIterations()
						).toHex();
	}
	
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 */
	public String hmacDigest(String plaintext) {
		return hmacDigest(plaintext,this.shiroProperties.getHmacSecretKey());
	}
	
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 */
	public String hmacDigest(String plaintext,String appKey) {
		return CryptoUtil.hmacDigest(plaintext,appKey,this.shiroProperties.getHmacAlg());
	}
	
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public StatelessLogined parseJwt(String jwt) {
		return parseJwt(jwt,this.shiroProperties.getJwtSecretKey());
	}
	
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public StatelessLogined parseJwt(String jwt,String appKey) {
		Claims claims = Jwts.parser()
				.setSigningKey(DatatypeConverter.parseBase64Binary(appKey))
				.parseClaimsJws(jwt)
				.getBody();
		StatelessLogined statelessAccount = new StatelessLogined();
		statelessAccount.setTokenId(claims.getId());// 令牌ID
		statelessAccount.setAppId(claims.getSubject());// 客户标识
		statelessAccount.setIssuer(claims.getIssuer());// 签发者
		statelessAccount.setIssuedAt(claims.getIssuedAt());// 签发时间
		statelessAccount.setAudience(claims.getAudience());// 接收方
		statelessAccount.setRoles(claims.get("roles", String.class));// 访问主张-角色
		statelessAccount.setPerms(claims.get("perms", String.class));// 访问主张-权限
		return statelessAccount;
	}

}