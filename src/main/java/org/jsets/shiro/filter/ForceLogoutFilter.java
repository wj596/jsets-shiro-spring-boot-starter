package org.jsets.shiro.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.config.ShiroProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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