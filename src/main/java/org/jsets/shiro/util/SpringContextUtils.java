package org.jsets.shiro.util;

import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;
/**
 * Spring上下文工具类
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 *
 */
public class SpringContextUtils{

	private static ApplicationContext CONTEXT = null;

    private static void check() {
    	Assert.notNull(SpringContextUtils.CONTEXT,"applicaitonContext  is null");
    }
    
    public static void setApplicationContext(ApplicationContext ctx) {
    	if(SpringContextUtils.CONTEXT == null) {
    		SpringContextUtils.CONTEXT = ctx;
    	}
    }
    
    public static ApplicationContext getApplicationContext() {
    	check();
        return SpringContextUtils.CONTEXT;
    }
    
    public static <T> T getBean(Class<T> requiredType) {
    	check();
        return SpringContextUtils.CONTEXT.getBean(requiredType);
    }
    
    public static <T> T getBean(String nameName) {
    	check();
        return (T) SpringContextUtils.CONTEXT.getBean(nameName);
    }
    
    public static <T> T tryBean(Class<T> requiredType) {
    	if(containsBean(requiredType))
    		return (T) SpringContextUtils.CONTEXT.getBean(requiredType);
    	return null;
    }
    
   public static boolean containsBean(Class<?> requiredType) {
	   check();
	   String[] exists = SpringContextUtils.CONTEXT.getBeanNamesForType(requiredType);
	   if(null!=exists&&exists.length>0) return  true;
       return  false;
    }

}