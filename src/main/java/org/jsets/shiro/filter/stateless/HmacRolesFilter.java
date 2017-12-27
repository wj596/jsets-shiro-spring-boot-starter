package org.jsets.shiro.filter.stateless;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.util.Commons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * 基于HMAC（ 散列消息认证码）的无状态资源过滤器
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 */
public class HmacRolesFilter extends HmacFilter{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(HmacAuthcFilter.class);


	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		Subject subject = getSubject(request, response); 
		if ((null == subject || !subject.isAuthenticated()) && isHmacSubmission(request)) {
			AuthenticationToken token = createToken(request, response);
			try {
				subject = getSubject(request, response);
				subject.login(token);
				return this.checkRoles(subject,mappedValue);
			} catch (AuthenticationException e) {
				LOGGER.error(e.getMessage(),e);
				Commons.restFailed(WebUtils.toHttp(response)
										,ShiroProperties.REST_CODE_AUTH_UNAUTHORIZED,e.getMessage());
			}	
		}
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        //未认证
        if (null == subject || !subject.isAuthenticated()) {
        	Commons.restFailed(WebUtils.toHttp(response)
        									,ShiroProperties.REST_CODE_AUTH_UNAUTHORIZED
        									,ShiroProperties.REST_MESSAGE_AUTH_UNAUTHORIZED);
        //未授权
        } else {
    		Commons.restFailed(WebUtils.toHttp(response)
											,ShiroProperties.REST_CODE_AUTH_FORBIDDEN
											,ShiroProperties.REST_MESSAGE_AUTH_FORBIDDEN);
        }
        return false;
	}
	
	private boolean checkRoles(Subject subject, Object mappedValue){
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) {
            return true;
        }
        List<String> roles = CollectionUtils.asList(rolesArray);
        System.out.println("checkRoles:"+roles);
        boolean[] hasRoles = subject.hasRoles(roles);
        for(boolean hasRole:hasRoles){
        	if(hasRole) return true;
        }
        return false;
	}
	
	
	
}