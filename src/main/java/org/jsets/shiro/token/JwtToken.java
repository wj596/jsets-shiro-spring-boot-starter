package org.jsets.shiro.token;
/**
 * JWT(json web token)令牌
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */
public class JwtToken extends StatelessToken{

	private static final long serialVersionUID = 1832943548774576547L;
	
	private String jwt;
	
	public JwtToken(String host,String jwt){
		super(host);
		this.jwt = jwt;
	}

	@Override
	public Object getPrincipal() {
		return this.jwt;
	}

	@Override
	public Object getCredentials() {
		return Boolean.TRUE;
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}
}