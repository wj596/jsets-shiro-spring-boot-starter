package org.jsets.shiro.util;

import java.util.Objects;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;


/**
 * Redis辅助工具类
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class RedisUtils {
	
	private static final GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();
	
	public static RedisTemplate<Object,Object> imitateRedisTemplate(){
		RedisConnectionFactory connFactory = SpringContextUtils.getBean(RedisConnectionFactory.class);
		if(Objects.nonNull(connFactory)) {
			RedisTemplate<Object, Object> nRedisTemplate = new RedisTemplate<Object, Object>();
			nRedisTemplate.setConnectionFactory(connFactory);
			nRedisTemplate.setKeySerializer(jsonSerializer);
			nRedisTemplate.setHashKeySerializer(jsonSerializer);
			nRedisTemplate.setBeanClassLoader(RedisUtils.class.getClassLoader());
			nRedisTemplate.afterPropertiesSet();
			return nRedisTemplate;
		}
		return null;
	}
	
	
}