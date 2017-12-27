package org.jsets.shiro.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 无状态令牌抽象
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */
public abstract class StatelessToken implements AuthenticationToken{

	private static final long serialVersionUID = 6655946030026745372L;

	private String host;// 客户IP
	
	public StatelessToken(String host){
		this.host = host;
	}
	
	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

}