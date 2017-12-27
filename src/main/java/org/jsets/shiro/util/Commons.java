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
package org.jsets.shiro.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.token.StatelessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * 系统工具
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public abstract class Commons {

	private static final Logger LOGGER = LoggerFactory.getLogger(Commons.class);

	/**
	 * 判断是否AJAX请求
	 */
	public static boolean isAjax(HttpServletRequest request) {
		return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
	}

	/**
	 * REST失败响应
	 */
	public static void restFailed(HttpServletResponse response,String code,String message) {
		respondJson(response,HttpServletResponse.SC_BAD_REQUEST,code,message);
	}
	
	/**
	 * AJAX成功响应
	 */
	public static void ajaxSucceed(HttpServletResponse response,String code,String message) {
		respondJson(response,HttpServletResponse.SC_OK,code,message);
	}
	
	/**
	 * AJAX失败响应
	 */
	public static void ajaxFailed(HttpServletResponse response
													,int respondStatus,String code,String message) {
		respondJson(response,respondStatus,code,message);
	}
	 
	/**
	 * JSON响应
	 */
	private static void respondJson(HttpServletResponse response
											, int respondStatus, String code,String message) {
		Map<String,String> map = Maps.newHashMap();
		map.put("code", code);
		map.put("message", message);
		response.setStatus(respondStatus);
		response.setCharacterEncoding("UTF-8");
		response.setContentType("application/json; charset=utf-8");
		PrintWriter out = null;
		try {
			out = response.getWriter();
			String json = new ObjectMapper().writeValueAsString(map);
			out.write(json);
		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		} finally {
			if (out != null)
				out.close();
		}
	}

	/**
	 * 设置信息
	 */
	public static void setAuthMessage(ServletRequest request, String message) { 
		 request.setAttribute(ShiroProperties.ATTRIBUTE_REQUEST_AUTH_MESSAGE, message); 
	}

	/**
	 * 分割字符串进SET
	 */
	public static Set<String> split(String str) {
		return split(str, ",");
	}

	/**
	 * 分割字符串进SET
	 */
	public static Set<String> split(String str, String separator) {
		Set<String> set = Sets.newLinkedHashSet();
		if (Strings.isNullOrEmpty(str))
			return set;
		for (String s : str.split(separator)) {
			set.add(s);
		}
		return set;
	}
	
	/**
	 * 分割字符串进SET
	 */
	public static Set<String> checkTimestamp(String str, String separator) {
		Set<String> set = Sets.newLinkedHashSet();
		if (Strings.isNullOrEmpty(str))
			return set;
		for (String s : str.split(separator)) {
			set.add(s);
		}
		return set;
	}
	
	/**
	 * 是否无状态令牌
	 */
	public static boolean isStatelessToken(Object token){
		return token instanceof StatelessToken;
	}
}