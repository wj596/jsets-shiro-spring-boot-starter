package org.jsets.shiro.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;

/**
 * 基于MAP的缓存管理器
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
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
