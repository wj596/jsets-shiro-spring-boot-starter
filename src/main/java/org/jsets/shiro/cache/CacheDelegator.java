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
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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