package org.jsets.shiro.filter;

import java.util.Locale;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.listener.AuthListenerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JsetsLogoutFilter extends LogoutFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(JsetsLogoutFilter.class);
	
	private final AuthListenerManager authListenerManager;
	
	public JsetsLogoutFilter(AuthListenerManager authListenerManager) {
		this.authListenerManager = authListenerManager;
	}
	
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);

        // Check if POST only logout is enabled
        if (isPostOnlyLogout()) {
            // check if the current request's method is a POST, if not redirect
            if (!WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
               return onLogoutRequestNotAPost(request, response);
            }
        }

        String redirectUrl = getRedirectUrl(request, response, subject);
        //try/catch added for SHIRO-298:
        try {
        	String account = (String) subject.getPrincipal();
            subject.logout();
            this.authListenerManager.onLogout(request, account);
        } catch (SessionException ise) {
        	LOGGER.debug("Encountered session exception during logout.  This can generally safely be ignored.", ise);
        }
        issueRedirect(request, response, redirectUrl);
        return false;
	}

}