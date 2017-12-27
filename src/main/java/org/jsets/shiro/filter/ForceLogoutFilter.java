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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.config.ShiroProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 强制用户下线过滤器
 * 
 * author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class ForceLogoutFilter extends JsetsAccessControlFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(ForceLogoutFilter.class);

	private final ShiroProperties shiroProperties;

	public ForceLogoutFilter(ShiroProperties shiroProperties) {
		this.shiroProperties = shiroProperties;
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		return false;
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		Subject subject = getSubject(request, response);
		if (!subject.isAuthenticated() && !subject.isRemembered()) {
			return this.respondLogin(request, response);
		}
		Session currentSession = subject.getSession();
        if (null!=currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_FORCE_LOGOUT)) {
        	subject.logout();
			return this.respondRedirect(request, response,this.shiroProperties.getForceLogoutUrl());
        }
        return true;
	}

}