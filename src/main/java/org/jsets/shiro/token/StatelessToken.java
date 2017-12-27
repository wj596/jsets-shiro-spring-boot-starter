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

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 无状态令牌抽象
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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