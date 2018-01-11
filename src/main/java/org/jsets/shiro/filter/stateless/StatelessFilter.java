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
package org.jsets.shiro.filter.stateless;

import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.token.HmacToken;
import org.jsets.shiro.token.JwtToken;
import org.jsets.shiro.util.Commons;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;

/**
 * 无状态过滤器--抽象父类
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 */
public abstract class StatelessFilter extends AccessControlFilter{

	protected boolean isHmacSubmission(ServletRequest request) {

		String appId = request.getParameter(ShiroProperties.PARAM_HMAC_APP_ID);
		String timestamp = request.getParameter(ShiroProperties.PARAM_HMAC_TIMESTAMP);
		String digest= request.getParameter(ShiroProperties.PARAM_HMAC_DIGEST);
		return (request instanceof HttpServletRequest)
							&& !Strings.isNullOrEmpty(appId)
							&& !Strings.isNullOrEmpty(timestamp)
							&& !Strings.isNullOrEmpty(digest);
	}
	
	protected AuthenticationToken createHmacToken(ServletRequest request, ServletResponse response) {
		
		String appId = request.getParameter(ShiroProperties.PARAM_HMAC_APP_ID);
		String timestamp = request.getParameter(ShiroProperties.PARAM_HMAC_TIMESTAMP);
		String digest= request.getParameter(ShiroProperties.PARAM_HMAC_DIGEST);
		List<String> parameterNames = Lists.newLinkedList();
		Enumeration<String> namesEnumeration = request.getParameterNames();
		while(namesEnumeration.hasMoreElements()){
            String parameterName = namesEnumeration.nextElement();
            parameterNames.add(parameterName);
        }
		StringBuilder baseString = new StringBuilder();
		parameterNames.stream()
			.sorted()
			.forEach(name -> {
				if(!ShiroProperties.PARAM_HMAC_APP_ID.equals(name)
					&&!ShiroProperties.PARAM_HMAC_TIMESTAMP.equals(name)
					&&!ShiroProperties.PARAM_HMAC_DIGEST.equals(name))
					baseString.append(request.getParameter(name));
		});
		baseString.append(appId);
		baseString.append(timestamp);
		String host = request.getRemoteHost();
		return new HmacToken( host, appId, timestamp, baseString.toString(), digest);
	}
	
	protected boolean isJwtSubmission(ServletRequest request) {
		String jwt = request.getParameter(ShiroProperties.PARAM_JWT);
		return (request instanceof HttpServletRequest) && !Strings.isNullOrEmpty(jwt);
	}
	
	protected AuthenticationToken createJwtToken(ServletRequest request, ServletResponse response) {
		String host = request.getRemoteHost();
		String jwt = request.getParameter(ShiroProperties.PARAM_JWT);
		return new JwtToken(host,jwt);
	}
	
	protected boolean checkRoles(Subject subject, Object mappedValue){
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) {
            return true;
        }
        return Stream.of(rolesArray)
        			.anyMatch(role->subject.hasRole(role));
	}
	
	protected boolean checkPerms(Subject subject, Object mappedValue){
        String[] perms = (String[]) mappedValue;
        boolean isPermitted = true;
        if (perms != null && perms.length > 0) {
            if (perms.length == 1) {
                if (!subject.isPermitted(perms[0])) {
                    isPermitted = false;
                }
            } else {
                if (!subject.isPermittedAll(perms)) {
                    isPermitted = false;
                }
            }
        }
        return isPermitted;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        //未认证
        if (null == subject || !subject.isAuthenticated()) {
        	Commons.restFailed(WebUtils.toHttp(response)
        								,MessageConfig.REST_CODE_AUTH_UNAUTHORIZED
        								,MessageConfig.REST_MESSAGE_AUTH_UNAUTHORIZED);
        //未授权
        } else {
    		Commons.restFailed(WebUtils.toHttp(response)
										,MessageConfig.REST_CODE_AUTH_FORBIDDEN
										,MessageConfig.REST_MESSAGE_AUTH_FORBIDDEN);
        }	
        return false;
	}
	
}