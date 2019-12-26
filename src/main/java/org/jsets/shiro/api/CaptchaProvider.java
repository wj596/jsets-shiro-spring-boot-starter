package org.jsets.shiro.api;

import java.awt.image.BufferedImage;

import javax.servlet.http.HttpServletRequest;

/**
 * 密码提供者接口 <br>
 * 应用系统实现这个接口以便使用自己的验证码
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月24日 下午2:55:15
 */
public interface CaptchaProvider {

	/**
	 * 生成验证码
	 */
	BufferedImage generateCaptcha(HttpServletRequest request);

	/**
	 * 验证码校验
	 */
	boolean validateCaptcha(HttpServletRequest request, String jcaptcha);
}