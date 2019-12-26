package org.jsets.shiro.config.internal;

import java.awt.Color;
import java.awt.Font;
import java.awt.image.BufferedImage;
import javax.servlet.http.HttpServletRequest;
import org.jsets.shiro.api.CaptchaProvider;
import com.octo.captcha.component.image.backgroundgenerator.UniColorBackgroundGenerator;
import com.octo.captcha.component.image.color.RandomListColorGenerator;
import com.octo.captcha.component.image.fontgenerator.RandomFontGenerator;
import com.octo.captcha.component.image.textpaster.NonLinearTextPaster;
import com.octo.captcha.component.image.wordtoimage.ComposedWordToImage;
import com.octo.captcha.component.word.wordgenerator.RandomWordGenerator;
import com.octo.captcha.engine.GenericCaptchaEngine;
import com.octo.captcha.image.gimpy.GimpyFactory;
import com.octo.captcha.service.CaptchaServiceException;
import com.octo.captcha.service.captchastore.FastHashMapCaptchaStore;
import com.octo.captcha.service.image.DefaultManageableImageCaptchaService;
import com.octo.captcha.service.image.ImageCaptchaService;

public class DefaultCaptchaProvider implements CaptchaProvider{

	@Override
	public BufferedImage generateCaptcha(HttpServletRequest request) {
		return jcaptchaService().getImageChallengeForID(request.getSession(true).getId());
	}

	@Override
	public boolean validateCaptcha(HttpServletRequest request, String jcaptcha) {
		try {
			String captchaID = request.getSession().getId();
			return jcaptchaService().validateResponseForID(captchaID, jcaptcha);
		} catch (CaptchaServiceException e) {
			return false;
		}
	}

	/**
	 * 获取验证码服务
	 */
	private ImageCaptchaService jcaptchaService() {
		return JCaptchaHolder.INSTANCE;
	}
	
	/**
	 * 随机字符
	 */
	private static final String ACCEPTED_CHARS = "1234567890abcdefghijklmnopkuvwxyz";
	
	
	/**
	 * 验证码服务实例持有者
	 */
	private static class JCaptchaHolder {  
	       private static final ImageCaptchaService INSTANCE = new DefaultManageableImageCaptchaService(
			 			new FastHashMapCaptchaStore(),
			 			new GenericCaptchaEngine(
			 					new GimpyFactory[]{new GimpyFactory(
			 							new RandomWordGenerator(ACCEPTED_CHARS)
			 							,new ComposedWordToImage(
			 									new RandomFontGenerator(20, 20,new Font[]{new Font("Arial", 20, 20)})
			 									,new UniColorBackgroundGenerator(90, 30, Color.white)
			 									,new NonLinearTextPaster(5, 5,
													 	new RandomListColorGenerator(new Color[] { 
													 		new Color(23, 170, 27)
													 		,new Color(220, 34, 11)
													 		,new Color(23, 67, 172) })
												))
			 			)}),180,100000, 75000);     
	}
}