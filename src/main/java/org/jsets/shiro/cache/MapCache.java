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

/**
 * 基于MAP的缓存
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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