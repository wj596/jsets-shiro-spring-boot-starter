package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.util.Commons;
/**
 * 权限过滤器,扩展自AuthorizationFilter增加了针对ajax请求的处理。
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 */
public abstract class JsetsAuthorizationFilter extends AuthorizationFilter{

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        Subject subject = getSubject(request, response);
        //未认证
        if (null == subject.getPrincipal()) {
    		if (Commons.isAjax(WebUtils.toHttp(request))) {
    			Commons.ajaxFailed(WebUtils.toHttp(response) 
    					,HttpServletResponse.SC_UNAUTHORIZED
    					,ShiroProperties.REST_CODE_AUTH_UNAUTHORIZED
    					,ShiroProperties.REST_MESSAGE_AUTH_UNAUTHORIZED);
    		}
            saveRequestAndRedirectToLogin(request, response);
        //未授权
        } else {
    		if (Commons.isAjax(WebUtils.toHttp(request))) {
    			Commons.ajaxFailed(WebUtils.toHttp(response) 
    					,HttpServletResponse.SC_FORBIDDEN
    					,ShiroProperties.REST_CODE_AUTH_FORBIDDEN
    					,ShiroProperties.REST_MESSAGE_AUTH_FORBIDDEN);
    		}else{
                String unauthorizedUrl = getUnauthorizedUrl();
                if (StringUtils.hasText(unauthorizedUrl)) {
                    WebUtils.issueRedirect(request, response, unauthorizedUrl);
                } else {
                    WebUtils.toHttp(response).sendError(HttpServletResponse.SC_FORBIDDEN);
                }
    		}
        }
        return false;
    }
    
}