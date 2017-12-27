package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.util.Commons;

public abstract class JsetsAccessControlFilter extends AccessControlFilter{

	/**
	 * 定位到登陆界面，返回false过滤器链停止
	 */
	protected boolean respondLogin(ServletRequest request, ServletResponse response) throws IOException{
		if (Commons.isAjax(WebUtils.toHttp(request))) {
			Commons.ajaxFailed(WebUtils.toHttp(response)
								,HttpServletResponse.SC_UNAUTHORIZED
								,ShiroProperties.REST_CODE_AUTH_UNAUTHORIZED
								,ShiroProperties.REST_MESSAGE_AUTH_UNAUTHORIZED);
			return false;// 过滤器链停止
		}
		saveRequestAndRedirectToLogin(request, response);
		return false;
	}
	
	/**
	 * 定位到指定界面，返回false过滤器链停止
	 */
	protected boolean respondRedirect(ServletRequest request, ServletResponse response,String redirectUrl) throws IOException{
		WebUtils.issueRedirect(request, response, redirectUrl);
		return false;
	}
	
}