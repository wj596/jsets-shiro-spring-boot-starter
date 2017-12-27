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
package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.service.ShiroAccountProvider;


/**
 * 认证过滤，器扩展自UserFilter：增加了针对ajax请求的处理
 * 
 * author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsUserFilter extends JsetsAccessControlFilter {

	private final ShiroAccountProvider accountService;

	public JsetsUserFilter(ShiroAccountProvider accountService){
		this.accountService = accountService;
	}

	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException{
		
		if (isLoginRequest(request, response)) {
			return true;
		} else {
			Subject subject = getSubject(request, response);
			if (subject.getPrincipal() != null) {//补齐SESSION中的信息
				Session session = subject.getSession();
				if (null==session.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER)) {
					String userId = (String) subject.getPrincipal();
					try{
						Account account = this.accountService.loadAccount(userId);
						session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER, account);
					}catch(AuthenticationException e){
						//log
						subject.logout();
					}
				}
				return true;
			}else{
				return false;
			}
		}
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return this.respondLogin(request, response);
	}
}