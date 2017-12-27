package org.jsets.shiro.token;

/**
 * HMAC(哈希消息认证码)令牌
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */
public class HmacToken extends StatelessToken{
	
	private static final long serialVersionUID = -7838912794581842158L;
	
	private String appId;// 客户标识
	private String timestamp;// 时间戳
	private String baseString;// 待核验字符串
	private String digest;// 消息摘要

	public HmacToken(String host,String appId,String timestamp,String baseString,String digest){
		super(host);
		this.appId = appId;
		this.timestamp = timestamp;
		this.baseString = baseString;
		this.digest = digest;
	}
	
	@Override
	public Object getPrincipal() {
		return this.appId;
	}
	@Override
	public Object getCredentials() {
		return Boolean.TRUE;
	}
	public String getAppId() {
		return appId;
	}
	public void setAppId(String appId) {
		this.appId = appId;
	}
	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public String getBaseString() {
		return baseString;
	}
	public void setBaseString(String baseString) {
		this.baseString = baseString;
	}
	public String getDigest() {
		return digest;
	}
	public void setDigest(String digest) {
		this.digest = digest;
	}
}