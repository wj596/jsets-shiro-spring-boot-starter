package org.jsets.shiro.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.util.JCaptchaUtil;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.util.Commons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Strings;

/**
 * 登陆过滤，器扩展自FormAuthenticationFilter：增加了针对ajax请求的处理、jcaptcha验证码
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class JsetsFormAuthenticationFilter extends FormAuthenticationFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(JsetsFormAuthenticationFilter.class);
	
	private final String DEFAULT_JCAPTCHA_PARAM = "shiro-form-jcaptcha";
	private final ShiroProperties shiroProperties;

	public JsetsFormAuthenticationFilter(ShiroProperties shiroProperties){
		this.shiroProperties = shiroProperties;
	}

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
    	System.out.println("    JsetsFormAuthenticationFilter ");
    	// 如果已经登陆，还停留在登陆页面，跳转到登陆成功页面
    	if (null != getSubject(request, response) && getSubject(request, response).isAuthenticated()) {
			if (isLoginRequest(request, response)) {
				try {
					issueSuccessRedirect(request, response);
					return true;
				} catch (Exception e) {
					LOGGER.error(e.getMessage(),e);
				}
			}
		}
    	// 父类判断是否放行
    	return super.isAccessAllowed(request,response,mappedValue);
    }
	
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    	if (isLoginRequest(request, response)) {
            if (isLoginSubmission(request, response)) {//是否登陆请求
                // 是否启用验证码
                if(this.shiroProperties.isJcaptchaEnable()){
                	String jcaptcha = WebUtils.getCleanParam(request, DEFAULT_JCAPTCHA_PARAM);
                	if(Strings.isNullOrEmpty(jcaptcha)){
                		return onJcaptchaFailure(request, response,"验证码为空");
                	}
                	if(!JCaptchaUtil.validateCaptcha(WebUtils.toHttp(request), jcaptcha)){
                		return onJcaptchaFailure(request, response,"验证码错误");
                	}
                }
                return executeLogin(request, response);
            } else {
                //allow them to see the login page ;)
                return true;
            }
        } else {
            saveRequestAndRedirectToLogin(request, response);
            return false;
        }
    }
	
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,ServletResponse response) throws Exception {
		if (Commons.isAjax(WebUtils.toHttp(request))) {
			Commons.ajaxSucceed(WebUtils.toHttp(response)
					, ShiroProperties.REST_CODE_AUTH_SUCCEED, ShiroProperties.REST_MESSAGE_AUTH_SUCCEED);
		} else {
			issueSuccessRedirect(request, response);
		}
		return false;
	}

	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		if (Commons.isAjax(WebUtils.toHttp(request))) {
			Commons.ajaxFailed(WebUtils.toHttp(response),HttpServletResponse.SC_UNAUTHORIZED
									, ShiroProperties.REST_CODE_AUTH_LOGIN_ERROR, e.getMessage());
			return false;// 过滤器链停止
		}
		setFailureAttribute(request, e);
		Commons.setAuthMessage(request,e.getMessage());
		return true;
	}
	
	protected boolean onJcaptchaFailure(ServletRequest request, ServletResponse response,String message) {
		if (Commons.isAjax(WebUtils.toHttp(request))) {
			Commons.ajaxFailed(WebUtils.toHttp(response),HttpServletResponse.SC_UNAUTHORIZED
											, ShiroProperties.REST_CODE_AUTH_LOGIN_ERROR, message);
			return false;// 过滤器链停止
		}
		Commons.setAuthMessage(request,message);
		return true;
	}


}