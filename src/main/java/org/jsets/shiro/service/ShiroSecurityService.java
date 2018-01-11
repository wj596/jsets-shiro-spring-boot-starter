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
package org.jsets.shiro.service;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.session.Session;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.StatelessLogined;
import org.jsets.shiro.util.ShiroUtils;
import io.jsonwebtoken.SignatureAlgorithm;
/**
 * 
 * 安全功能聚合服务类
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 * 
 */ 

public class ShiroSecurityService {
	
	/**
	 * 生成密码
	 * @param plaintext 明文
	 */
	public String password(String plaintext) {
		return ShiroUtils.password(plaintext);
	}
	/**
	 * 签发JWT
	 * @param subject 用户名称
	 * @param issuer 签发人
	 * @param period 有效时间
	 * @param roles 访问主张-角色
	 * @param permissions 访问主张-资源
	 * @param algorithm 算法
	 * @return JSON WEB TOKEN
	 */
	public String issueJwt(String subject,String issuer,Long period,String roles,String permissions,SignatureAlgorithm algorithm) {
		return ShiroUtils.issueJwt(subject,issuer,period,roles,permissions,algorithm);
	}
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public StatelessLogined parseJwt(String jwt) {
		return ShiroUtils.parseJwt(jwt);
	}
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public String hmacDigest(String plaintext,String appKey) {
		return ShiroUtils.hmacDigest(plaintext,appKey);
	}
	/**
	 * 获取当前登陆的用户
	 */
	public Account getUser() {
		return ShiroUtils.getUser();
	}
	/**
	 * 当前用户是否拥有角色
	 * @param roleName 角色名称
	 */
	public boolean hasRole(String roleName) {
		return ShiroUtils.hasRole(roleName);
	}
	/**
	 * 当前用户是否拥有权限
	 * @param permName 权限名称
	 */
	public boolean hasPerms(String permName) {
		return ShiroUtils.hasPerms(permName);
	}
	
	/**
	 * 当前用户切换成switchUserId的身份
	 */
	public void runAs(String switchUserId) {
		ShiroUtils.runAs(switchUserId); 
	}
	
	/**
	 * 当前用户是否以切换的身份运行
	 */
	public boolean isRunAs() {
		return ShiroUtils.isRunAs(); 
	}
	
	/**
	 * 当前用户是否以切换的身份运行，还原到上一身份
	 */
	public void releaseRunAs() {
		ShiroUtils.releaseRunAs();  
	}
	/**
	 * 设置认证信息
	 */
	public void setAuthMessage(HttpServletRequest request, String message) { 
		ShiroUtils.setAuthMessage(request, message); 
	}
	/**
	 * 获取活跃的SESSION数量
	 */
	public int getActiveSessionCount() {
		return ShiroUtils.getActiveSessionCount();
	}
	/**
	 * 获取活跃的SESSION
	 */
	public  List<Session> getActiveSessions() {
		return ShiroUtils.getActiveSessions();
	}
	/**
	 * 强制退出
	 * @param sessionId 退出的sessionId
	 */
	public boolean forceLogout(String sessionId) {
		return ShiroUtils.forceLogout(sessionId);
	}
	
	/**
	 * 删除account的认证、授权缓存
	 * <br>如果启用了auth缓存，当用户的认证信息和角色信息发生了改变，一定要执行此操作。
	 * <br>否则只能等到用户再次登录这些变更才能生效。
	 */
	public void clearAuthCache(String account) {
		ShiroUtils.clearAuthCache(account);
	}
	
	/**
	 * 刷新动态过滤规则
	 * <br>如果角色-资源对应关系发生编号，可以通过此方法进行同步刷新，从而达到URL动态过滤的效果。
	 */
	public void reloadFilterRules() {
		ShiroUtils.reloadFilterRules();
	}
}