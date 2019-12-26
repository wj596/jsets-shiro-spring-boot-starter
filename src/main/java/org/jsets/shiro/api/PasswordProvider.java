package org.jsets.shiro.api;

/**
 * 密码提供者接口
 * <br>
 * 应用系统实现这个接口以便使用自己的加密算法
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */ 
public interface PasswordProvider {
	
	/**
	 *    加密
	 * @param plainPassord 明文密码
	 * @return 密文密码
	 */
	String encrypt(String plainPassord);

}