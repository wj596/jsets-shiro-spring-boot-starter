package org.jsets.shiro.token;

import org.apache.shiro.authc.AuthenticationToken;

public class UsernameToken  implements AuthenticationToken{

	private static final long serialVersionUID = 1L;
	
	private String host;// 客户IP
	private String username;

	public UsernameToken(String host,String username){
		this.host = host;
		this.username = username;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public Object getPrincipal() {
		return this.username;
	}

	@Override
	public Object getCredentials() {
		return Boolean.TRUE;
	}

}