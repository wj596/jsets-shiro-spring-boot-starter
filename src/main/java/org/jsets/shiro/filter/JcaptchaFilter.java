/*
 * Copyright 2017-2018 the original author(https://github.com/wj596)
 * 
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </p>
 */
package org.jsets.shiro.filter;

import java.awt.image.BufferedImage;
import java.io.IOException;
import javax.imageio.ImageIO;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.web.servlet.OncePerRequestFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.api.CaptchaProvider;


/**
 * 验证码生成过滤器
 * 
 * author wangjie (https://github.com/wj596)
 * 
 * @date 2016年6月31日
 *
 */
public class JcaptchaFilter extends OncePerRequestFilter {

	private final CaptchaProvider captchaProvider;

	public JcaptchaFilter(CaptchaProvider captchaProvider) {
		this.captchaProvider = captchaProvider;
	}

	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		httpResponse.setHeader("Cache-Control", "no-store");
		httpResponse.setHeader("Pragma", "no-cache");
		httpResponse.setDateHeader("Expires", 0);
		httpResponse.setContentType("image/jpeg");
		ServletOutputStream output = httpResponse.getOutputStream();
		try {
			BufferedImage image = this.captchaProvider.generateCaptcha(WebUtils.toHttp(request));
			ImageIO.write(image, "jpg", output);
			output.flush();
		} finally {
			output.close();
		}
	}
}