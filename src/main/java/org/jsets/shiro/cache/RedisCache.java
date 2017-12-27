package org.jsets.shiro.cache;

import java.util.Collection;
import java.util.Set;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.springframework.data.redis.core.HashOperations;

public class RedisCache<K,V> implements Cache<K,V>{

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

	@Override
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
	
	
}
