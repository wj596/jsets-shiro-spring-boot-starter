package org.jsets.shiro.handler;
/**
 * 密码连续错误次数超限处理器
 * 
 * @author wangjie
 */
public interface PasswdRetryLimitHandler {

	public void handle(String account);
	
}