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
package org.jsets.shiro.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.token.StatelessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import io.jsonwebtoken.lang.Assert;

/**
 * 辅助工具类
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public abstract class Commons {

	private static final Logger LOGGER = LoggerFactory.getLogger(Commons.class);
	
	public static final String JCAPTCHA_URL = "/jcaptcha.jpg";
	public static final String FILTER_ANON = "anon";
	public static final String FILTER_AUTHC = "authc";
	public static final String FILTER_JCAPTCHA = "jcaptcha";
	public static final String FILTER_ROLES = "roles";
	public static final String FILTER_PERMS = "perms";
	public static final String FILTER_USER = "user";
	public static final String FILTER_KEEP_ONE = "keepOne";
	public static final String FILTER_FORCE_LOGOUT = "forceLogout";
	public static final String FILTER_HMAC = "hmac";
	public static final String FILTER_HMAC_ROLES = "hmacRoles";
	public static final String FILTER_HMAC_PERMS = "hmacPerms";
	public static final String FILTER_JWT = "jwt";
	public static final String FILTER_JWT_ROLES = "jwtRoles";
	public static final String FILTER_JWT_PERMS = "jwtPerms";
	
	public static final short CACHE_TYPE_MAP = 0;
	public static final short CACHE_TYPE_EHCACHE = 1;
	public static final short CACHE_TYPE_REDIS = 2;
	public static final short CACHE_TYPE_OTHER = 3;
	
	public static final String REMEMBERME_COOKIE_NAME = "rememberMeCookie";
	

	private static final ObjectMapper MAPPER = new ObjectMapper(); 
	private static CompressionCodecResolver CODECRESOLVER = new DefaultCompressionCodecResolver();
	
	/**
	 * 判断是否AJAX请求
	 */
	public static boolean isAjax(HttpServletRequest request) {
		return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
	}

	/**
	 * REST失败响应
	 */
	public static void restFailed(HttpServletResponse response,String code,String message) {
		respondJson(response,HttpServletResponse.SC_BAD_REQUEST,code,message);
	}
	
	/**
	 * AJAX成功响应
	 */
	public static void ajaxSucceed(HttpServletResponse response,String code,String message) {
		respondJson(response,HttpServletResponse.SC_OK,code,message);
	}
	
	/**
	 * AJAX失败响应
	 */
	public static void ajaxFailed(HttpServletResponse response
													,int respondStatus,String code,String message) {
		respondJson(response,respondStatus,code,message);
	}
	 
	/**
	 * JSON响应
	 */
	private static void respondJson(HttpServletResponse response
											, int respondStatus, String code,String message) {
		Map<String,String> map = Maps.newHashMap();
		map.put("code", code);
		map.put("message", message);
		response.setStatus(respondStatus);
		response.setCharacterEncoding("UTF-8");
		response.setContentType("application/json; charset=utf-8");
		PrintWriter out = null;
		try {
			out = response.getWriter();
			String json = new ObjectMapper().writeValueAsString(map);
			out.write(json);
		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		} finally {
			if (out != null)
				out.close();
		}
	}

	/**
	 * 设置信息
	 */
	public static void setAuthMessage(ServletRequest request, String message) { 
		request.setAttribute(ShiroProperties.ATTRIBUTE_REQUEST_AUTH_MESSAGE,message);
	}

	/**
	 * 分割字符串进SET
	 */
	public static Set<String> split(String str) {
		return split(str, ",");
	}

	/**
	 * 分割字符串进SET
	 */
	public static Set<String> split(String str, String separator) {
		
		Set<String> set = Sets.newLinkedHashSet();
		if (Strings.isNullOrEmpty(str))
			return set;
		for (String s : str.split(separator)) {
			set.add(s);
		}
		return set;
	}
	
	/**
	 * 分割字符串进SET
	 */
	public static Set<String> checkTimestamp(String str, String separator) {
		Set<String> set = Sets.newLinkedHashSet();
		if (Strings.isNullOrEmpty(str))
			return set;
		for (String s : str.split(separator)) {
			set.add(s);
		}
		return set;
	}
	
	/**
	 * 是否无状态令牌
	 */
	public static boolean isStatelessToken(Object token){
		return token instanceof StatelessToken;
	}
	
	/**
	 * 对象转JSON
	 */
	public static String toJson(Object object){
		try {
			 return MAPPER.writeValueAsString(object);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		} 
		return null;
	}

	/**
	 * JSON转对象
	 */
	public static <T> T fromJson(String json,Class<T> valueType){
		try {
			return MAPPER.readValue(json,valueType);
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}
	
	/**
	 * JSON转对象
	 */
	public static boolean hasLen(String string){
		return !Strings.isNullOrEmpty(string);
	}
	
	/**
	 * 解析JWT的Payload
	 */
	public static String parseJwtPayload(String jwt){
        Assert.hasText(jwt, "JWT String argument cannot be null or empty.");
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;
        int delimiterCount = 0;
        StringBuilder sb = new StringBuilder(128);
        for (char c : jwt.toCharArray()) {
            if (c == '.') {
                CharSequence tokenSeq = io.jsonwebtoken.lang.Strings.clean(sb);
                String token = tokenSeq!=null?tokenSeq.toString():null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedPayload = token;
                }

                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }
        if (sb.length() > 0) {
            base64UrlEncodedDigest = sb.toString();
        }
        if (base64UrlEncodedPayload == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a body/payload.");
        }
        // =============== Header =================
        Header header = null;
        CompressionCodec compressionCodec = null;
        if (base64UrlEncodedHeader != null) {
            String origValue = TextCodec.BASE64URL.decodeToString(base64UrlEncodedHeader);
            Map<String, Object> m = readValue(origValue);
            if (base64UrlEncodedDigest != null) {
                header = new DefaultJwsHeader(m);
            } else {
                header = new DefaultHeader(m);
            }
            compressionCodec = CODECRESOLVER.resolveCompressionCodec(header);
        }
        // =============== Body =================
        String payload;
        if (compressionCodec != null) {
            byte[] decompressed = compressionCodec.decompress(TextCodec.BASE64URL.decode(base64UrlEncodedPayload));
            payload = new String(decompressed, io.jsonwebtoken.lang.Strings.UTF_8);
        } else {
            payload = TextCodec.BASE64URL.decodeToString(base64UrlEncodedPayload);
        }
        return payload;
    }
	public static Map<String, Object> readValue(String val) {
	     try {
	            return MAPPER.readValue(val, Map.class);
	     } catch (IOException e) {
	            throw new MalformedJwtException("Unable to read JSON value: " + val, e);
	     }
	}
}