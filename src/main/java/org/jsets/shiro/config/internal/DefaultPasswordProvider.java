package org.jsets.shiro.config.internal;

import org.apache.shiro.crypto.hash.SimpleHash;
import org.jsets.shiro.api.PasswordProvider;
import org.jsets.shiro.config.ShiroProperties;

/**
 * 默认密码服务
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class DefaultPasswordProvider implements PasswordProvider{

	private final ShiroProperties properties;
	
	public DefaultPasswordProvider(ShiroProperties properties) {
		this.properties = properties;
	}

	@Override
	public String encrypt(String plainPassord) {
		return new SimpleHash(
						this.properties.getPasswdAlg()
						,plainPassord
						,this.properties.getPasswdSalt()
						,this.properties.getPasswdIterations()
			   ).toHex();
	}

}