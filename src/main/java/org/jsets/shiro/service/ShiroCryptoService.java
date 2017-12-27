package org.jsets.shiro.service;

import javax.xml.bind.DatatypeConverter;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessAccount;
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
 * @date 2016年6月24日 下午2:55:15
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
	public String hmacDigest(String plaintext,String appKey) {
		if(Strings.isNullOrEmpty(appKey))
			appKey = this.shiroProperties.getHmacSecretKey();
		return CryptoUtil.hmacDigest(plaintext,appKey
						 ,this.shiroProperties.getHmacAlg());
	}
	
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public StatelessAccount parseJwt(String jwt) {
		Claims claims = Jwts.parser()
				.setSigningKey(DatatypeConverter.parseBase64Binary(this.shiroProperties.getJwtSecretKey()))
				.parseClaimsJws(jwt)
				.getBody();
		StatelessAccount statelessAccount = new StatelessAccount();
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