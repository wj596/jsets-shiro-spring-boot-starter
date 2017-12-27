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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;

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

	public void setRedisTemplate(RedisTemplate redisTemplate) {
		//ConnectionFactory ConnectionFactoryredisTemplate.getConnectionFactory()
	    GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();  
	    //redisTemplate.setKeySerializer(jsonSerializer);
	    //redisTemplate.setHashKeySerializer(jsonSerializer);
	    //redisTemplate.setValueSerializer(jsonSerializer);
	   // redisTemplate.setHashValueSerializer(jsonSerializer);
		this.redisTemplate = redisTemplate;
	}
}