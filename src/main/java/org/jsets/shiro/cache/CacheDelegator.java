package org.jsets.shiro.cache;

import java.util.concurrent.atomic.AtomicInteger;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.jsets.shiro.config.ShiroProperties;

/**
 * cache功能委托类
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class CacheDelegator {
	
	private CacheManager cacheManager;
	private final Object cacheMonitor = new Object();

	/**
	 * 获取并增加密码重试次数
	 */
	public int incPasswdRetryCount(String account){
		Cache<String,Integer> cache = 
				   this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_PASSWORD_RETRY);
		synchronized (cacheMonitor) {
			Integer count = cache.get(account);
			if (null == count) {
				count = new Integer(0);
			}
			cache.put(account,++count);
			return count;
		}
	}
	/**
	 * 清扫密码重试次数
	 */
	public void cleanPasswdRetryCount(String account){
		Cache<String,AtomicInteger> cache = 
				   this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_PASSWORD_RETRY);
		cache.remove(account);
	}
	
	/**
	 * 获取保持登陆状态的用户
	 */
	public String getKeepUser(String account){
		
		Cache<String,String> cache = 
				    this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_KEEP_ONE_USER);
		return cache.get(account);
	}
	
	/**
	 * 缓存保持登陆状态的用户
	 */
	public String putKeepUser(String account,String sessionId){
		
		Cache<String,String> cache = 
				    this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_KEEP_ONE_USER);
		return cache.put(account, sessionId);
	}
	
	/**
	 * 清扫账号对应的认证、授权缓存
	 */
	public void clearAuthCache(String account,String realmName){
		synchronized (cacheMonitor) {
			Cache<String, AuthenticationInfo> authenticationCache = 
				    this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_AUTHENTICATION);
			Cache<Object,AuthorizationInfo> authorizationCache = 
				     this.getCacheManager().getCache(ShiroProperties.CACHE_NAME_AUTHORIZATION);
			authenticationCache.remove(account);
			authorizationCache.remove(new SimplePrincipalCollection(account,realmName));
		}
	}
	
	public CacheManager getCacheManager() {
		return cacheManager;
	}
	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}
}