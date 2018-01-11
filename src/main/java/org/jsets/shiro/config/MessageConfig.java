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
package org.jsets.shiro.config;

/**
 * 用户提示信息配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class MessageConfig {
	
	private MessageConfig(){};
	
	private static class MessagesHolder{
		private static MessageConfig MESSAGES = new MessageConfig();
	}
	protected static MessageConfig ins(){
		  return MessagesHolder.MESSAGES;
	}

	// 验证码为空
	public static final String MSG_CAPTCHA_EMPTY = "验证码不能为空";
	// 验证码错误
	public static final String MSG_CAPTCHA_ERROR = "验证码错误";
	// 账号密码为空
	public static final String MSG_ACCOUNT_PASSWORD_EMPTY = "账号和密码均不能为空";
	// 账号不存在
	public static final String MSG_ACCOUNT_NOT_EXIST = "账号不存在";
	// 账号异常
	public static final String MSG_ACCOUNT_EXCEPTION = "账号异常";
	// 账号或密码错误
	public static final String MSG_ACCOUNT_PASSWORD_ERROR = "账号或密码错误";
	// 密码重试错误
	public static final String MSG_PASSWORD_RETRY_ERROR = "密码输入错误 {total} 次账号将被锁定, 您还能再试 {remain} 次";
	// 验证码为空
	public static final String MSG_BURNED_TOKEN = "签名/令牌已经作废";
	// 找不到秘钥
	public static final String MSG_NO_SECRET_KEY = "找不验签秘钥";
	// 签名无效
	public static final String MSG_HMAC_ERROR = "hmac签名无效";
	// 签名过期
	public static final String MSG_HMAC_TIMEOUT = "hmac签名超时失效";
	// 令牌无效
	public static final String MSG_JWT_ERROR = "jwt无效";
	// 令牌过期
	public static final String MSG_JWT_TIMEOUT = "jwt令牌超时失效";
	// 令牌格式错误
	public static final String MSG_JWT_MALFORMED = "jwt格式错误";
	// 令牌签名无效
	public static final String MSG_JWT_SIGNATURE = "jwt签名无效";
	// REST编码-身份验证成功
	public static final String REST_CODE_AUTH_SUCCEED = "auth:succeed";
	// REST消息-身份验证成功
	public static final String REST_MESSAGE_AUTH_SUCCEED = "身份验证成功";
	// REST编码-身份验证失败
	public static final String REST_CODE_AUTH_LOGIN_ERROR = "auth:login_error";
	// REST消息-身份验证失败
	public static final String REST_MESSAGE_AUTH_LOGIN_ERROR = "身份验证失败";
	// REST编码-需要身份验证
	public static final String REST_CODE_AUTH_UNAUTHORIZED = "auth:unauthorized";
	// REST消息-需要身份验证
	public static final String REST_MESSAGE_AUTH_UNAUTHORIZED = "需要身份验证";
	// REST编码-权限不足
	public static final String REST_CODE_AUTH_FORBIDDEN = "auth:forbidden";
	// REST消息-权限不足
	public static final String REST_MESSAGE_AUTH_FORBIDDEN = "权限不足";
	// REST编码-无用户
	public static final String REST_CODE_AUTH_USER_NOT_FOUND = "auth:user_not_found";
	// REST编码-密码错误
	public static final String REST_CODE_AUTH_NO_PERMISSION = "auth:bad_password";
	// REST编码-未知错误
	public static final String REST_CODE_INTERNAL_UNKNOWN_ERROR = "internal:unknown_error";

 	// 验证码为空
	private String msgCaptchaEmpty = MSG_CAPTCHA_EMPTY;
	// 验证码错误
	private String msgCaptchaError = MSG_CAPTCHA_ERROR;
	// 账号密码为空
	private String msgAccountPasswordEmpty = MSG_ACCOUNT_PASSWORD_EMPTY;
	// 账号不存在
	private String msgAccountNotExist = MSG_ACCOUNT_NOT_EXIST;
	// 账号异常
	private String msgAccountException = MSG_ACCOUNT_EXCEPTION;
	// 账号或密码错误
	private String msgAccountPasswordError = MSG_ACCOUNT_PASSWORD_ERROR;
	// 密码重试错误
	private String msgPasswordRetryError = MSG_PASSWORD_RETRY_ERROR;
	// 签名无效
	private String msgHmacError = MSG_HMAC_ERROR;
	// 签名过期
	private String msgHmacTimeout = MSG_HMAC_TIMEOUT;
	// 令牌无效
	private String msgJwtError = MSG_JWT_ERROR;
	// 令牌过期
	private String msgJwtTimeout = MSG_JWT_TIMEOUT;
	// 令牌格式错误
	private String msgJwtMalformed = MSG_JWT_MALFORMED;
	// 令牌签名无效
	private String msgJwtSignature = MSG_JWT_SIGNATURE;
	
	/**
	 * 设置提示信息-验证码为空
	 */
	public void setMsgCaptchaEmpty(String msgCaptchaEmpty) {
		this.msgCaptchaEmpty = msgCaptchaEmpty;
	}
	/**
	 * 设置提示信息-验证码错误
	 */
	public void setMsgCaptchaError(String msgCaptchaError) {
		this.msgCaptchaError = msgCaptchaError;
	}
	/**
	 * 设置提示信息-账号或者密码为空
	 */
	public void setMsgAccountPasswordEmpty(String msgAccountPasswordEmpty) {
		this.msgAccountPasswordEmpty = msgAccountPasswordEmpty;
	}
	/**
	 * 设置提示信息-账号不存在
	 */
	public void setMsgAccountNotExist(String msgAccountNotExist) {
		this.msgAccountNotExist = msgAccountNotExist;
	}
	/**
	 * 设置提示信息-账号异常
	 */
	public void setMsgAccountException(String msgAccountException) {
		this.msgAccountException = msgAccountException;
	}
	/**
	 * 设置提示信息-账号或密码错误
	 */
	public void setMsgAccountPasswordError(String msgAccountPasswordError) {
		this.msgAccountPasswordError = msgAccountPasswordError;
	}
	/**
	 * 设置提示信息-密码重试错误，提供两个站位符：最大次数{total}、剩余次数：{remain}
	 * <br>默认：密码错误{total}次账号将被锁定,您还可以重试：{remain}次
	 */
	public void setMsgPasswordRetryError(String msgPasswordRetryError) {
		this.msgPasswordRetryError = msgPasswordRetryError;
	}
	/**
	 * 设置提示信息-hmac签名无效
	 */
	public void setMsgHmacError(String msgHmacError) {
		this.msgHmacError = msgHmacError;
	}
	/**
	 * 设置提示信息-hmac签名超时
	 */
	public void setMsgHmacTimeout(String msgHmacTimeout) {
		this.msgHmacTimeout = msgHmacTimeout;
	}
	/**
	 * 设置提示信息-jwt无效
	 */
	public void setMsgJwtError(String msgJwtError) {
		this.msgJwtError = msgJwtError;
	}
	/**
	 * 设置提示信息-jwt超时
	 */
	public void setMsgJwtTimeout(String msgJwtTimeout) {
		this.msgJwtTimeout = msgJwtTimeout;
	}
	/**
	 * 设置提示信息-jwt格式错误
	 */
	public void setMsgJwtMalformed(String msgJwtMalformed) {
		this.msgJwtMalformed = msgJwtMalformed;
	}
	/**
	 * 设置提示信息-jwt签名错误
	 */
	public void setMsgJwtSignature(String msgJwtSignature) {
		this.msgJwtSignature = msgJwtSignature;
	}
	public String getMsgCaptchaEmpty() {
		return msgCaptchaEmpty;
	}
	public String getMsgCaptchaError() {
		return msgCaptchaError;
	}
	public String getMsgAccountPasswordEmpty() {
		return msgAccountPasswordEmpty;
	}
	public String getMsgAccountNotExist() {
		return msgAccountNotExist;
	}
	public String getMsgAccountException() {
		return msgAccountException;
	}
	public String getMsgAccountPasswordError() {
		return msgAccountPasswordError;
	}
	public String getMsgPasswordRetryError() {
		return msgPasswordRetryError;
	}
	public String getMsgHmacError() {
		return msgHmacError;
	}
	public String getMsgHmacTimeout() {
		return msgHmacTimeout;
	}
	public String getMsgJwtError() {
		return msgJwtError;
	}
	public String getMsgJwtTimeout() {
		return msgJwtTimeout;
	}
	public String getMsgJwtMalformed() {
		return msgJwtMalformed;
	}
	public String getMsgJwtSignature() {
		return msgJwtSignature;
	}
}