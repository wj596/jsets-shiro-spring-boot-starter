package org.jsets.shiro.model;

import java.io.Serializable;

/**
 * 账号的抽象，应用中的用户实体要实现这个接口
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
 */ 
public interface Account extends Serializable{
	/**
	 * 获取用户名
	 */
	public String getAccount();
	/**
	 * 获取登陆口令
	 */
	public String getPassword();
}