package org.jsets.shiro.filter.stateless;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.util.Commons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HmacAuthcFilter extends HmacFilter{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(HmacAuthcFilter.class);

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		Subject subject = getSubject(request, response); 
		if (null != subject && subject.isAuthenticated()) {
			return true;
		}
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		if(isHmacSubmission(request)){
			AuthenticationToken token = createToken(request, response);
			try {
				Subject subject = getSubject(request, response);
				subject.login(token);
				return true;
			} catch (AuthenticationException e) {
				LOGGER.error(e.getMessage(),e);
				Commons.restFailed(WebUtils.toHttp(response)
									,ShiroProperties.REST_CODE_AUTH_UNAUTHORIZED,e.getMessage());
			}
		}
		return false;
	}

}