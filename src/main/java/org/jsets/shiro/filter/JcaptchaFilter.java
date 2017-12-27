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
import org.jsets.shiro.util.JCaptchaUtil;

public class JcaptchaFilter extends OncePerRequestFilter {  

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
            BufferedImage image = JCaptchaUtil.generateCaptcha(WebUtils.toHttp(request));
            ImageIO.write(image, "jpg", output);
            output.flush();  
        } finally {  
        	output.close();  
        }
		
	}
}