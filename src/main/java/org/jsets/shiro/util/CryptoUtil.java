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
package org.jsets.shiro.util;

import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.common.base.Strings;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 安全加密相关工具类
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public abstract class CryptoUtil {
	/**
	 * 签发令牌
	 * @param id 令牌ID
	 * @param subject 用户ID
	 * @param issuer 签发人
	 * @param period 有效时间(毫秒)
	 * @param roles 访问主张-角色
	 * @param permissions 访问主张-权限
	 * @param algorithm 加密算法
	 * @return json web token 
	 */
	public static String issueJwt(String jwtSecretKey,String id
								  ,String subject,String issuer,Long period,String roles
									 ,String permissions,SignatureAlgorithm algorithm) {
		// 当前时间戳(精确到毫秒)
		long currentTimeMillis = System.currentTimeMillis();
		// 秘钥
		byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);
		JwtBuilder jwt  =  Jwts.builder();
		if(!Strings.isNullOrEmpty(id)) jwt.setId(id);
		// 用户名
		jwt.setSubject(subject);
		// 签发者
		if(!Strings.isNullOrEmpty(issuer)) jwt.setIssuer(issuer);
		// 签发时间
		jwt.setIssuedAt(new Date(currentTimeMillis));
		// 有效时间
		if(null != period){
			Date expiration = new Date(currentTimeMillis+period);
			jwt.setExpiration(expiration);
		}
		// 访问主张-角色
		if(!Strings.isNullOrEmpty(roles)) jwt.claim("roles", roles);
		// 访问主张-权限
		if(!Strings.isNullOrEmpty(permissions)) jwt.claim("perms", permissions);
		jwt.compressWith(CompressionCodecs.DEFLATE);
		jwt.signWith(algorithm, secretKeyBytes);
		return jwt.compact();
	}
	
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 * @param secretKey 安全秘钥
	 * @param alg 算法
	 * @return 摘要
	 */
	public static String hmacDigest(String plaintext,String secretKey,String alg) {
		try {
			Mac mac = Mac.getInstance(alg);
			byte[] secretByte = secretKey.getBytes();
			byte[] dataBytes = plaintext.getBytes();
			SecretKey secret = new SecretKeySpec(secretByte,alg);
			mac.init(secret);
			byte[] doFinal = mac.doFinal(dataBytes);
			return byte2HexStr(doFinal);
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private static String byte2HexStr(byte[] b)  { 
        String stmp=""; 
        StringBuilder sb = new StringBuilder(""); 
        for (int n=0;n<b.length;n++) 
        { 
            stmp = Integer.toHexString(b[n] & 0xFF); 
            sb.append((stmp.length()==1)? "0"+stmp : stmp); 
            sb.append(" "); 
        } 
        return sb.toString().toUpperCase().trim(); 
    }
}