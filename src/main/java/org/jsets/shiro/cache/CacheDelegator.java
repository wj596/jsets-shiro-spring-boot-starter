package org.jsets.shiro.cache;

import java.util.concurrent.atomic.AtomicInteger;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.jsets.shiro.config.ShiroProperties;

public class CacheDelegator {
	
	private final CacheManager cacheManager;
	private final Object cacheMonitor = new Object();
	
	public CacheDelegator(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}

	/**
	 * 获取并增加密码重试次数
	 */
	public int incPasswdRetryCount(String account) {
		Cache<String, Integer> cache = this.cacheManager.getCache(ShiroProperties.CACHE_NAME_PASSWORD_RETRY);
		synchronized (cacheMonitor) {
			Integer count = cache.get(account);
			if (null == count) {
				count = new Integer(0);
			}
			cache.put(account, ++count);
			return count;
		}
	}

	/**
	 * 清扫密码重试次数
	 */
	public void cleanPasswdRetryCount(String account) {
		Cache<String, AtomicInteger> cache = this.cacheManager.getCache(ShiroProperties.CACHE_NAME_PASSWORD_RETRY);
		cache.remove(account);
	}

	/**
	 * 获取保持登陆状态的用户
	 */
	public String getKeepUser(String account) {
		Cache<String, String> cache = this.cacheManager.getCache(ShiroProperties.CACHE_NAME_KEEP_ONE_USER);
		return cache.get(account);
	}

	/**
	 * 缓存保持登陆状态的用户
	 */
	public String putKeepUser(String account, String sessionId) {
		Cache<String, String> cache = this.cacheManager.getCache(ShiroProperties.CACHE_NAME_KEEP_ONE_USER);
		return cache.put(account, sessionId);
	}

	/**
	 * 清扫账号对应的认证、授权缓存
	 */
	public void clearAuthCache(String account, String realmName) {
		synchronized (cacheMonitor) {
			Cache<String, AuthenticationInfo> authenticationCache = this.cacheManager
					.getCache(ShiroProperties.CACHE_NAME_AUTHENTICATION);
			Cache<Object, AuthorizationInfo> authorizationCache = this.cacheManager
					.getCache(ShiroProperties.CACHE_NAME_AUTHORIZATION);
			authenticationCache.remove(account);
			authorizationCache.remove(new SimplePrincipalCollection(account, realmName));
		}
	}

	/**
	 * 销毁token
	 * <>
	 * 如果tokean是销毁过的，返回true
	 */
	public boolean burnedToken(String token) {
		Cache<String, Integer> cache = this.cacheManager.getCache(ShiroProperties.CACHE_NAME_TOKEN_BURNERS);
		Integer burned = cache.get(token);
		if (null == burned) {
			cache.put(token, Integer.valueOf(0));
			return false;
		}
		return true;
	}
	
}