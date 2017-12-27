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
 * 基于MAP的缓存管理器
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
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