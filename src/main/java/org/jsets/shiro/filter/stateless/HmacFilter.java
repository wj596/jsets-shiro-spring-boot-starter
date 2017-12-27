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

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.token.HmacToken;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;

/**
 * 基于HMAC（ 散列消息认证码）的无状态过滤器--抽象父类
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 */
public abstract class HmacFilter extends AccessControlFilter{
	
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
		String appId = request.getParameter(ShiroProperties.PARAM_HMAC_APP_ID);
		String timestamp = request.getParameter(ShiroProperties.PARAM_HMAC_TIMESTAMP);
		String digest= request.getParameter(ShiroProperties.PARAM_HMAC_DIGEST);
		List<String> parameterNames = Lists.newLinkedList();
		Enumeration<String> namesEnumeration = request.getParameterNames();
		while(namesEnumeration.hasMoreElements()){
            String parameterName = namesEnumeration.nextElement();
            parameterNames.add(parameterName);
        }
		Collections.sort(parameterNames);// 排序参数->自然顺序
		StringBuilder baseString = new StringBuilder();
		for (String parameterName : parameterNames) {
			if(!ShiroProperties.PARAM_HMAC_APP_ID.equals(parameterName)
				&&!ShiroProperties.PARAM_HMAC_TIMESTAMP.equals(parameterName)
				&&!ShiroProperties.PARAM_HMAC_DIGEST.equals(parameterName)){
				baseString.append(request.getParameter(parameterName));
			}
		}
		baseString.append(appId);
		baseString.append(timestamp);
		String host = request.getRemoteHost();
		return new HmacToken( host, appId, timestamp, baseString.toString(), digest);
	}
	
	protected boolean isHmacSubmission(ServletRequest request) {

		String appId = request.getParameter(ShiroProperties.PARAM_HMAC_APP_ID);
		String timestamp = request.getParameter(ShiroProperties.PARAM_HMAC_TIMESTAMP);
		String digest= request.getParameter(ShiroProperties.PARAM_HMAC_DIGEST);
		return (request instanceof HttpServletRequest)
							&& !Strings.isNullOrEmpty(appId)
							&& !Strings.isNullOrEmpty(timestamp)
							&& !Strings.isNullOrEmpty(digest);
	}
}