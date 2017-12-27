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
package org.jsets.shiro.token;

/**
 * HMAC(哈希消息认证码)令牌
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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