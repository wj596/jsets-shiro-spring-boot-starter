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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;

/**
 * 基于MAP的缓存管理器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@SuppressWarnings("all")
public class MapCacheManager implements CacheManager{

	
	private final ConcurrentMap<String, Cache> CACHES = new ConcurrentHashMap<String, Cache>(); 
	
	@Override
	public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
		Cache<K, V> cache = CACHES.get(cacheName);  
        if (null == cache) {  
        	cache = new MapCache<K, V>(cacheName);  
            CACHES.put(cacheName, cache);  
        }  
        return cache;  
	}

}
