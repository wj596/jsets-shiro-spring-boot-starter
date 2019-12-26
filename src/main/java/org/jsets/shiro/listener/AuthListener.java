package org.jsets.shiro.listener;

import java.util.Date;
import javax.servlet.ServletRequest;

public interface AuthListener {
	/**
	 * 登录成功
	 * @param request http请求
	 * @param account 账号
	 */
	void onLoginSuccess(ServletRequest request,String account);
	
	/**
	 * 登录失败
	 * @param request http请求
	 * @param account 账号
	 * @param reason  登录失败原因原因
	 */
	void onLoginFailure(ServletRequest request,String account,String reason);
	
	/**
	 * 登出
	 * @param request http请求
	 * @param account 账号
	 */
	void onLogout(ServletRequest request,String account);
	

	/**
	 * 
	 * 用户被踢出
	 * @param request http请求
	 * @param account 账号
	 * @param loginedHost 已登录HOST
	 * @param loginedTime 已登时间
	 * 
	 * 
	 * 如：账号admin在机器A登录，
	 * 再有人用admin在机器B登录，
	 * 会触发此事件，loginedHost为机器A的HOST,loginedTime为在机器A登录的时间
	 * 
	 * 
	 */
	void onKeepOneKickout(ServletRequest request,String account,String loginedHost,Date loginedTime);
	
	
	/**
	 * 
	 * 强制用户下线
	 * @param request http请求
	 * @param account 账号
	 * 
	 */
	void onForceLogout(ServletRequest request,String account);
	
	
	/**
	 * 访问断言
	 * @param request http请求
	 * @param account 账号
	 * @param needRoles 访问资源需要的角色
	 * @param allowed 是否允许访问
	 */
	void onAccessAssert(ServletRequest request,String account,String needRoles,boolean allowed);
}
