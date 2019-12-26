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

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * 基于REDIS的缓存管理器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@SuppressWarnings("all")
public class RedisCacheManager implements CacheManager{

	private RedisTemplate redisTemplate;
	private final ConcurrentMap<String, Cache> CACHES = new ConcurrentHashMap<String, Cache>(); 
	
	@Override
	public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
		Cache<K, V> cache = CACHES.get(cacheName);  
        if (null == cache) {  
        	cache = new RedisCache<K, V>(redisTemplate.opsForHash(),cacheName);  
            CACHES.put(cacheName, cache);  
        }  
        return cache;  
	}
	
	public void setRedisTimeout(String cacheName,long timeout) {
		this.redisTemplate.expire(cacheName, timeout, TimeUnit.SECONDS);
	}

	public void setRedisTemplate(RedisTemplate redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	
	public RedisTemplate getRedisTemplate() {
		return redisTemplate;
	}

	/**
	 * 基于REDIS的缓存
	 *
	 * @author wangjie (https://github.com/wj596)
	 * @date 2016年6月31日
	 */
	public static class RedisCache<K,V> implements Cache<K,V>{

		private final HashOperations<String,K,V> redisTemplate;
		private final String cacheName; 
		
		public RedisCache(HashOperations<String,K,V> redisTemplate,String cacheName){
			this.redisTemplate = redisTemplate;
			this.cacheName = cacheName;
		}

		@Override
		public void clear() throws CacheException {
			this.redisTemplate.delete(cacheName, keys());
		}

		@Override
		public V get(K key) throws CacheException {
			return this.redisTemplate.get(cacheName, key);
		}

		@Override
		public Set<K> keys() {
			return this.redisTemplate.keys(cacheName);
		}

		public V put(K key, V value) throws CacheException {
			this.redisTemplate.put(cacheName, key, value);
			return this.redisTemplate.get(cacheName, key);
		}

		@Override
		public V remove(K key) throws CacheException {
			V v = this.redisTemplate.get(cacheName, key);
			this.redisTemplate.delete(cacheName, key);
			return v;
		}

		@Override
		public int size() {
			return this.redisTemplate.size(cacheName).intValue();
		}

		@Override
		public Collection<V> values() {
			return this.redisTemplate.values(cacheName);
		}
		
		@Override
		public String toString() {
			return "cacheName:"+this.cacheName+",size:"+this.size();
		}
	}
}