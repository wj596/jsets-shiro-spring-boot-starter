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
	private static class MessageConfigHolder{
		private static MessageConfig MESSAGECONFIG = new MessageConfig();
	}
	public static MessageConfig instance(){
		  return MessageConfigHolder.MESSAGECONFIG;
	}
	
	public static final String MSG_ACCOUNT_EXCEPT = "账号异常";
	public static final String MSG_ACCOUNT_NOT_EXIST = "账号不存在";
	public static final String MSG_AUTHC_ERROR = "账号或密码错误";
	public static final String MSG_PASSWD_RETRY_ERROR = "密码错误{total}次账号将会锁定,您还可以重试：{remain}次";
	public static final String MSG_HMAC_ERROR = "签名无效";
	public static final String MSG_HMAC_TIMEOUT = "签名过期";
	public static final String MSG_JWT_ERROR = "令牌无效";
	public static final String MSG_JWT_TIMEOUT = "令牌过期";
	public static final String MSG_JWT_MALFORMED = "令牌格式错误";
	public static final String MSG_JWT_SIGNATURE = "令牌签名错误";
	
	// REST编码-认证成功
	public static final String REST_CODE_AUTH_SUCCEED = "auth:succeed";
	// REST消息-认证成功
	public static final String REST_MESSAGE_AUTH_SUCCEED = "身份验证成功";
	// REST编码-认证失败
	public static final String REST_CODE_AUTH_LOGIN_ERROR = "auth:login_error";
	// REST消息-认证失败
	public static final String REST_MESSAGE_AUTH_LOGIN_ERROR = "身份验证失败";
	// REST编码-未认证
	public static final String REST_CODE_AUTH_UNAUTHORIZED = "auth:unauthorized";
	// REST消息-未认证
	public static final String REST_MESSAGE_AUTH_UNAUTHORIZED = "需要身份验证";
	// REST编码-未授权
	public static final String REST_CODE_AUTH_FORBIDDEN = "auth:forbidden";
	// REST消息-未授权
	public static final String REST_MESSAGE_AUTH_FORBIDDEN = "权限不足";
	// REST编码-无用户
	public static final String REST_CODE_AUTH_USER_NOT_FOUND = "auth:user_not_found";
	// REST编码-密码错误
	public static final String REST_CODE_AUTH_NO_PERMISSION = "auth:bad_password";
	// REST编码-未知错误
	public static final String REST_CODE_INTERNAL_UNKNOWN_ERROR = "internal:unknown_error";
	
	
	private String msgAccountExcept = MSG_ACCOUNT_EXCEPT;// 账号异常
	private String msgAccountNotExist = MSG_ACCOUNT_NOT_EXIST;// 账号不存在
	private String msgAuthcError = MSG_AUTHC_ERROR;// 账号或密码错误
	private String msgPasswdRetryError = MSG_PASSWD_RETRY_ERROR;// 密码错误,您还可以重试：{remain}次
	private String msgHmacError = MSG_HMAC_ERROR;// 签名无效
	private String msgHmacTimeout = MSG_HMAC_TIMEOUT;// 签名过期
	private String msgJwtError = MSG_JWT_ERROR;// 令牌无效
	private String msgJwtTimeout = MSG_JWT_TIMEOUT;// 令牌过期
	private String msgJwtMalformed = MSG_JWT_MALFORMED;// 令牌格式错误
	private String msgJwtSignature = MSG_JWT_SIGNATURE;// 令牌签名错误
	
	/**
	 * 账号异常,默认：账号异常
	 */
	public void setMsgAccountExcept(String msgAccountExcept) {
		this.msgAccountExcept = msgAccountExcept;
	}
	/**
	 * 账号不存在,默认：账号不存在
	 */
	public void setMsgAccountNotExist(String msgAccountNotExist) {
		this.msgAccountNotExist = msgAccountNotExist;
	}
	/**
	 * 认证失败,默认：账号或密码错误
	 */
	public void setMsgAuthcError(String msgAuthcError) {
		this.msgAuthcError = msgAuthcError;
	}
	/**
	 * 设置密码重试错误提示,提供两个站位符：最大次数{total}、剩余次数：{remain}
	 * <br>默认：密码错误{total}次账号将被锁定,您还可以重试：{remain}次
	 */
	public void setMsgPasswdRetryError(String msgPasswdRetryError) {
		this.msgPasswdRetryError = msgPasswdRetryError;
	}
	/**
	 * hmac验证失败,默认：签名无效
	 */
	public void setMsgHmacError(String msgHmacError) {
		this.msgHmacError = msgHmacError;
	}
	/**
	 * hmac签名过期,默认：签名过期
	 */
	public void setMsgHmacTimeout(String msgHmacTimeout) {
		this.msgHmacTimeout = msgHmacTimeout;
	}
	/**
	 * jwt验证失败,默认：令牌无效
	 */
	public void setMsgJwtError(String msgJwtError) {
		this.msgJwtError = msgJwtError;
	}
	/**
	 * jwt令牌过期,默认：令牌过期
	 */
	public void setMsgJwtTimeout(String msgJwtTimeout) {
		this.msgJwtTimeout = msgJwtTimeout;
	}
	/**
	 * jwt令牌格式错误,默认：令牌格式错误
	 */
	public void setMsgJwtMalformed(String msgJwtMalformed) {
		this.msgJwtMalformed = msgJwtMalformed;
	}
	/**
	 * jwt令牌签名错误,默认：令牌签名错误
	 */
	public void setMsgJwtSignature(String msgJwtSignature) {
		this.msgJwtSignature = msgJwtSignature;
	}
	
	
	public String getMsgAccountExcept() {
		return msgAccountExcept;
	}
	public String getMsgAccountNotExist() {
		return msgAccountNotExist;
	}
	public String getMsgAuthcError() {
		return msgAuthcError;
	}
	public String getMsgPasswdRetryError() {
		return msgPasswdRetryError;
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