package org.jsets.shiro.config;

import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.filter.ForceLogoutFilter;
import org.jsets.shiro.filter.JcaptchaFilter;
import org.jsets.shiro.filter.JsetsFormAuthenticationFilter;
import org.jsets.shiro.filter.JsetsPermissionsAuthorizationFilter;
import org.jsets.shiro.filter.JsetsRolesAuthorizationFilter;
import org.jsets.shiro.filter.JsetsUserFilter;
import org.jsets.shiro.filter.KeepOneUserFilter;
import org.jsets.shiro.filter.stateless.HmacAuthcFilter;
import org.jsets.shiro.filter.stateless.HmacRolesFilter;
import org.jsets.shiro.filter.stateless.JwtFilter;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.HmacRule;
import org.jsets.shiro.model.JwtRule;
import org.jsets.shiro.model.PermRule;
import org.jsets.shiro.model.RoleRule;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;

/**
 * 过滤器构造器
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class FilterChainConfig{
	
	private ShiroFilteRulesProvider shiroFilteRulesProvider;
	private final Map<String, Filter> filters = Maps.newLinkedHashMap();
	
	
	public ShiroFilteRulesProvider getShiroFilteRulesProvider() {
		return shiroFilteRulesProvider;
	}
	public void setShiroFilteRulesProvider(ShiroFilteRulesProvider shiroFilteRulesProvider) {
		this.shiroFilteRulesProvider = shiroFilteRulesProvider;
	}
	public void addFilter(String name,Filter filter) {
		this.filters.put(name, filter);
	}
	public Map<String, Filter> getFilters() {
		return filters;
	}
}