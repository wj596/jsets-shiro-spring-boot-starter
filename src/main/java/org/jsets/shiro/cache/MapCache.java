package org.jsets.shiro.cache;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

/**
 * 基于MAP的缓存
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class MapCache<K,V> implements Cache<K,V>{

	private final ConcurrentMap<K,V> storge = new ConcurrentHashMap<K,V>(); 
	private final String cacheName; 
	
	public MapCache(String cacheName){
		this.cacheName = cacheName;
	}
	
	@Override
	public void clear() throws CacheException {
		storge.clear();
	}

	@Override
	public V get(K key) throws CacheException {
		return storge.get(key);
	}

	@Override
	public Set<K> keys() {
		return storge.keySet();
	}

	@Override
	public V put(K key, V value) throws CacheException {
		return storge.put(key, value);
	}

	@Override
	public V remove(K key) throws CacheException {
		return storge.remove(key);
	}

	@Override
	public int size() {
		return storge.size();
	}

	@Override
	public Collection<V> values() {
		return storge.values();
	}

	@Override
	public String toString() {
		return "cacheName:"+this.cacheName+",size:"+this.size();
	}

}