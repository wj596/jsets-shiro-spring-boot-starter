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
 * JWT(json web token)令牌
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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