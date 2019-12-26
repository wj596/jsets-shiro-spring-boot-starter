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
package org.jsets.shiro.listener;

import org.apache.shiro.authc.AuthenticationException;

/**
 * 密码连续错误次数超限处理器接口
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public interface PasswdRetryLimitListener {

	/**
	 * 处理
	 * @param account 账号
	 * @param maxRetries 最大重试次数
	 * @param retries 重试次数
	 */
	public void handle(String account,int maxRetries,int retries) throws AuthenticationException;
	
}