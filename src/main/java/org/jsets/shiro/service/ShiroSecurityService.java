package org.jsets.shiro.service;

import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.jsets.shiro.config.JsetsSecurityManager;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.StatelessAccount;
import org.jsets.shiro.realm.StatelessThreadContext;
import org.jsets.shiro.service.ShiroCryptoService;
import org.jsets.shiro.util.CryptoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import com.google.common.collect.Lists;
import io.jsonwebtoken.SignatureAlgorithm;
/**
 * 安全相关功能提供者
 * <br>这是一个聚合的工具类，将与shiro安全相关的功能提供给应用系统
 * 
 * @author wangjie (https://github.com/wj596) 
 * @date 2016年6月24日 下午2:55:15
 */ 
public class ShiroSecurityService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ShiroSecurityService.class);
	
	@Autowired
	private ShiroProperties shiroProperties;
	@Autowired
	private ShiroCryptoService cryptoService;
	private final JsetsSecurityManager securityManager;
	
	public ShiroSecurityService(JsetsSecurityManager securityManager){
		this.securityManager = securityManager;
	}

	/**
	 * 生成密码
	 * @param plaintext 明文
	 */
	public String password(String plaintext) {
		return this.cryptoService.password(plaintext);
	}
	/**
	 * 签发JWT
	 * @param id 令牌ID
	 * @param subject 用户名称
	 * @param issuer 签发人
	 * @param period 有效时间
	 * @param roles 访问主张-角色
	 * @param permissions 访问主张-资源
	 * @param algorithm 算法
	 * @return JSON WEB TOKEN
	 */
	public String issueJwt(String id,String subject,String issuer,Long period
			,String roles,String permissions,SignatureAlgorithm algorithm) {
		return CryptoUtil.issueJwt(this.shiroProperties.getJwtSecretKey()
				, id, subject, issuer, period, roles, permissions, algorithm);
	}
	/**
	 * 验签JWT
	 * 
	 * @param jwt json web token
	 */
	public StatelessAccount parseJwt(String jwt) {
		return this.cryptoService.parseJwt(jwt);
	}
	/**
	 * 生成HMAC摘要
	 * 
	 * @param plaintext 明文
	 * @param appKey 秘钥
	 */
	public String hmacDigest(String plaintext,String appKey) {
		return this.cryptoService.hmacDigest(plaintext,appKey);
	}
	/**
	 * 获取当前登陆的用户
	 */
	public Account getUser() {
		Session currentSession = SecurityUtils.getSubject().getSession(false);
		if(null != currentSession){
			return (Account) currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER);
		} else{
			return StatelessThreadContext.getAccount();
		}
	}
	/**
	 * 当前用户是否拥有角色
	 * @param roleName 角色名称
	 */
	public boolean hasRole(String roleName) {
		return SecurityUtils.getSubject().hasRole(roleName);
	}
	/**
	 * 当前用户是否拥有权限
	 * @param permName 权限名称
	 */
	public boolean hasPerms(String permName) {
		try{
			SecurityUtils.getSubject().checkPermission("testPermission");
			return true;
		}catch(AuthorizationException e){
			//不处理	
		}
		return false;
	}
	
	/**
	 * 当前用户切换成switchUserId的身份
	 */
	public void runAs(String switchUserId) {
		SecurityUtils.getSubject().runAs(new SimplePrincipalCollection(switchUserId, "")); 
	}
	
	/**
	 * 当前用户是否以切换的身份运行
	 */
	public boolean isRunAs() {
		return SecurityUtils.getSubject().isRunAs(); 
	}
	
	/**
	 * 当前用户是否以切换的身份运行，还原到上一身份
	 */
	public void releaseRunAs() {
		if(isRunAs()){
			SecurityUtils.getSubject().releaseRunAs();  
		}
	}
	/**
	 * 设置认证信息
	 */
	public void setAuthMessage(HttpServletRequest request, String message) { 
		 request.setAttribute(ShiroProperties.ATTRIBUTE_REQUEST_AUTH_MESSAGE, message); 
	}
	/**
	 * 获取活跃的SESSION数量
	 */
	public int getActiveSessionCount() {
		return this.securityManager.getSessionManager().getSessionDAO().getActiveSessions().size();
	}
	/**
	 * 获取活跃的SESSION
	 */
	public List<Session> getActiveSessions() {
		return Collections.unmodifiableList(
				Lists.newArrayList(this.securityManager.getSessionManager().getSessionDAO().getActiveSessions())
			   );
	}
	/**
	 * 强制退出
	 * @param sessionId 退出的sessionId
	 */
	public boolean forceLogout(String sessionId) {
		try {
			Session session = this.securityManager.getSessionManager().getSession(new DefaultSessionKey(sessionId));
			if (session != null) {
				session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_FORCE_LOGOUT, Boolean.TRUE);
			}
			return Boolean.TRUE;
		} catch (UnknownSessionException e) { 
			LOGGER.warn(e.getMessage());
		}
		return Boolean.FALSE;
	}
	
	/**
	 * 删除account的认证、授权缓存
	 * <br>如果启用了auth缓存，当用户的认证信息和角色信息发生了改变，一定要执行此操作。
	 * <br>否则只能等到用户再次登录这些变更才能生效。
	 */
	public void clearAuthCache(String account) {
		for(Realm cachedRealm:this.securityManager.getCachedRealms()){
			this.securityManager.getCacheDelegator().clearAuthCache(account,cachedRealm.getName());
		}
	}
	
	/**
	 * 刷新动态过滤规则
	 * <br>如果角色-资源对应关系发生编号，可以通过此方法进行同步刷新，从而达到URL动态过滤的效果。
	 */
	public void reloadFilterRules() {
		this.securityManager.reloadFilterRules(this.shiroProperties);
	}
}