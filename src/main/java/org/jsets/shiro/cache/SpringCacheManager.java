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
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.springframework.cache.Cache.ValueWrapper;

/**
 * 
 * spring CacheManager包装
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
@SuppressWarnings("all")
public class SpringCacheManager implements CacheManager{

	private final org.springframework.cache.CacheManager delegator;
	
	private final ConcurrentMap<String, SpringCache> CACHES = new ConcurrentHashMap<String, SpringCache>();
	
	public SpringCacheManager(org.springframework.cache.CacheManager cacheManager){
		this.delegator = cacheManager;
	}
	
	@Override
	public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
		SpringCache<K,V> cache = this.CACHES.get(cacheName);
		if (cache != null) {
			return cache;
		}
		else {
			synchronized (this.CACHES) {
				cache = this.CACHES.get(cacheName);
				if (cache == null) {
					org.springframework.cache.Cache springCache = this.delegator.getCache(cacheName);
					cache = new SpringCache(cacheName,springCache);
					this.CACHES.put(cacheName, cache);
				}
				return cache;
			}
		}
	}
	
	/**
	 * 
	 * spring Cache包装
	 * 
	 * @author wangjie (https://github.com/wj596)
	 * @date 2016年6月31日
	 *
	 */
	public static class SpringCache<K,V> implements Cache<K,V>{

		private final String cacheName; 
		private final org.springframework.cache.Cache delegator;
		
		public SpringCache(String cacheName,org.springframework.cache.Cache cache){
			this.cacheName = cacheName;
			this.delegator = cache;
		}
		
		@Override
		public void clear() throws CacheException {
			this.delegator.clear();
		}

		@Override
		public V get(K key) throws CacheException {
			ValueWrapper wrapper = this.delegator.get(key);
			return wrapper == null ? null : (V) wrapper.get();
		}

		@Override
		public V put(K key, V value) throws CacheException {
			this.delegator.put(key, value);
			return value;
		}

		@Override
		public V remove(K key) throws CacheException {
			V v = this.get(key);
			this.delegator.evict(key);
			return v;
		}

		@Override
		public Set<K> keys() {
			throw new UnsupportedOperationException(" not supported ");
		}
		
		@Override
		public int size() {
			throw new UnsupportedOperationException(" not supported ");
		}

		@Override
		public Collection<V> values() {
			throw new UnsupportedOperationException(" not supported ");
		}

		@Override
		public String toString() {
			return "cacheName:"+this.cacheName;
		}
	}
}