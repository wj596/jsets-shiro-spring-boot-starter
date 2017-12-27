package org.jsets.shiro.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Strings;

/**
 * 保持账号唯一用户登陆
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 * 
 */
public class KeepOneUserFilter extends JsetsAccessControlFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(KeepOneUserFilter.class);
	
	private final ShiroProperties shiroProperties;
	private final SessionManager sessionManager;
	private final CacheDelegator cacheDelegate;

	public KeepOneUserFilter(ShiroProperties shiroProperties,SessionManager sessionManager
																	,CacheDelegator cacheDelegate) {
		this.shiroProperties = shiroProperties;
		this.sessionManager = sessionManager;
		this.cacheDelegate = cacheDelegate;
	}
	
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		if(!this.shiroProperties.isKeepOneEnabled()) return true;
		return false;
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		Subject subject = getSubject(request, response);
		if (!subject.isAuthenticated() && !subject.isRemembered()) {
			return this.respondLogin(request, response);
		}
		String account = (String) subject.getPrincipal();
		String loginedSessionId = this.cacheDelegate.getKeepUser(account);
		Session currentSession = subject.getSession();
		String currentSessionId = (String) currentSession.getId();
		
		if(currentSessionId.equals(loginedSessionId)) {
			return true;
		} else if (Strings.isNullOrEmpty(loginedSessionId)){
			this.cacheDelegate.putKeepUser(account, currentSessionId);
        	return true;
		} else if (null==currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT)) {
			this.cacheDelegate.putKeepUser(account, currentSessionId);
			try{
				Session loginedSession = this.sessionManager.getSession(new DefaultSessionKey(loginedSessionId));
				if(null != loginedSession){
					loginedSession.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT,Boolean.TRUE);
				}
			} catch(SessionException e){
				LOGGER.warn(e.getMessage());
			}
		}
        if (null!=currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT)) {
        	subject.logout();
			return this.respondRedirect(request, response,this.shiroProperties.getKickoutUrl());
        }

		return true;
	}

}