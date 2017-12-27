package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.service.ShiroAccountProvider;


/**
 * 认证过滤，器扩展自UserFilter：增加了针对ajax请求的处理
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class JsetsUserFilter extends JsetsAccessControlFilter {

	private final ShiroAccountProvider accountService;

	public JsetsUserFilter(ShiroAccountProvider accountService){
		this.accountService = accountService;
	}

	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException{
		
		if (isLoginRequest(request, response)) {
			return true;
		} else {
			Subject subject = getSubject(request, response);
			if (subject.getPrincipal() != null) {//补齐SESSION中的信息
				Session session = subject.getSession();
				if (null==session.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER)) {
					String userId = (String) subject.getPrincipal();
					try{
						Account account = this.accountService.loadAccount(userId);
						session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER, account);
					}catch(AuthenticationException e){
						//log
						subject.logout();
					}
				}
				return true;
			}else{
				return false;
			}
		}
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return this.respondLogin(request, response);
	}
}