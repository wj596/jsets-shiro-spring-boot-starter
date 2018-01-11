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
package org.jsets.shiro.filter;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.servlet.Filter;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.IllegalConfigException;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.filter.stateless.HmacAuthcFilter;
import org.jsets.shiro.filter.stateless.HmacPermsFilter;
import org.jsets.shiro.filter.stateless.HmacRolesFilter;
import org.jsets.shiro.filter.stateless.JwtAuthcFilter;
import org.jsets.shiro.filter.stateless.JwtPermsFilter;
import org.jsets.shiro.filter.stateless.JwtRolesFilter;
import org.jsets.shiro.model.AuthorizeRule;
import org.jsets.shiro.model.CustomRule;
import org.jsets.shiro.model.RolePermRule;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import org.jsets.shiro.util.Commons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.collect.Maps;
/**
 * FILTER 管理器
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class FilterManager {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(FilterManager.class);
	
	private ShiroProperties properties;
	private DefaultWebSessionManager sessionManager;
	private CacheDelegator cacheDelegator;
	private MessageConfig messages;
	private ShiroAccountProvider accountProvider;
	private ShiroFilteRulesProvider rulesProvider;
	private Map<String, Filter> customFilters;
	private String loginUrl;
	private String successUrl;
	private String unauthorizedUrl;
	private Map<String, Filter> statefulFilters = Maps.newLinkedHashMap();
	private Map<String, Filter> statelessFilters = Maps.newLinkedHashMap();
	private Map<String, String> anonFilterChain = Maps.newLinkedHashMap();
	private Map<String, String> staticFilterChain = Maps.newLinkedHashMap();
	private Map<String, String> dynamicFilterChain = Maps.newLinkedHashMap();
	private final Object reloadMonitor = new Object();
	
	
	
	public void initFixations(){
		this.loginUrl = this.properties.getLoginUrl();
		this.successUrl = this.properties.getLoginSuccessUrl();
		this.unauthorizedUrl = this.properties.getUnauthorizedUrl();
	}
	
	public void initFilters(){
		this.statefulFilters.putAll(this.customFilters);
		JsetsFormAuthenticationFilter formFilter = new JsetsFormAuthenticationFilter();
		formFilter.setProperties(this.properties);
		formFilter.setMessages(this.messages);
		this.statefulFilters.putIfAbsent(Commons.FILTER_AUTHC, formFilter);
		
		if (properties.isJcaptchaEnable()) {
			JcaptchaFilter jcaptchaFilter = new JcaptchaFilter();
			this.statefulFilters.putIfAbsent(Commons.FILTER_JCAPTCHA, jcaptchaFilter);
		}
		
		JsetsRolesAuthorizationFilter rolesFilter = new JsetsRolesAuthorizationFilter();
		this.statefulFilters.putIfAbsent(Commons.FILTER_ROLES, rolesFilter);
		
		JsetsPermissionsAuthorizationFilter permsFilter = new JsetsPermissionsAuthorizationFilter();
		this.statefulFilters.putIfAbsent(Commons.FILTER_PERMS, permsFilter);
		
		JsetsUserFilter userFilter = new JsetsUserFilter();
		userFilter.setAccountService(this.accountProvider);
		this.statefulFilters.putIfAbsent(Commons.FILTER_USER, userFilter);
		
		if (this.properties.isKeepOneEnabled()) {
			KeepOneUserFilter keepOneFilter = new KeepOneUserFilter();
			keepOneFilter.setProperties(this.properties);
			keepOneFilter.setSessionManager(this.sessionManager);
			keepOneFilter.setCacheDelegate(this.cacheDelegator);
			this.statefulFilters.putIfAbsent(Commons.FILTER_KEEP_ONE, keepOneFilter);
		}
		if (this.properties.isForceLogoutEnable()) {
			ForceLogoutFilter forceFilter = new ForceLogoutFilter();
			forceFilter.setProperties(this.properties);
			this.statefulFilters.putIfAbsent(Commons.FILTER_FORCE_LOGOUT, forceFilter);
		}
		if (this.properties.isHmacEnabled()) {
			HmacAuthcFilter hmacFilter = new HmacAuthcFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_HMAC, hmacFilter);
			HmacRolesFilter hmacRolesFilter = new HmacRolesFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_HMAC_ROLES, hmacRolesFilter);
			HmacPermsFilter hmacPermsFilter = new HmacPermsFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_HMAC_PERMS, hmacPermsFilter);
		}
		if (this.properties.isJwtEnabled()) {
			JwtAuthcFilter jwtFilter = new JwtAuthcFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_JWT, jwtFilter);
			JwtRolesFilter jwtRolesFilter = new JwtRolesFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_JWT_ROLES, jwtRolesFilter);
			JwtPermsFilter jwtPermsFilter = new JwtPermsFilter();
			this.statelessFilters.putIfAbsent(Commons.FILTER_JWT_PERMS, jwtPermsFilter);
		}
	}
	
	public void initFilterChain(){
		// ------------anon
		ShiroProperties.DEFAULT_IGNORED.forEach(ignored 
								-> this.anonFilterChain.put(ignored, Commons.FILTER_ANON));
		if(Commons.hasLen(this.properties.getKickoutUrl()))
			this.anonFilterChain.put(properties.getKickoutUrl(), Commons.FILTER_ANON);
		if(Commons.hasLen(properties.getForceLogoutUrl()))
			this.anonFilterChain.put(properties.getForceLogoutUrl(), Commons.FILTER_ANON);
		// ------------static
		if (this.properties.isJcaptchaEnable())
			this.staticFilterChain.put(Commons.JCAPTCHA_URL, Commons.FILTER_JCAPTCHA);
		this.properties.getFilteRules().forEach(rule->{
			if(rule.split("-->").length!=2) 
				throw new IllegalConfigException("过滤规则配置不正确,格式：url->filters");
			Stream.of(rule.split("-->")[0].split(","))
					.forEach(url->this.staticFilterChain.put(url, rule.split("-->")[1]));
		});
		// ------------dynamic
		this.buildDynamicFilterChain();
	}
	
	public void reloadFilterChain(final ShiroFilterFactoryBean shiroFilterFactoryBean) {
		synchronized (reloadMonitor) {
			AbstractShiroFilter abstractShiroFilter = null;
			try {
				abstractShiroFilter = (AbstractShiroFilter) shiroFilterFactoryBean.getObject();
				PathMatchingFilterChainResolver filterChainResolver = (PathMatchingFilterChainResolver) abstractShiroFilter.getFilterChainResolver();
				DefaultFilterChainManager filterChainManager = (DefaultFilterChainManager) filterChainResolver.getFilterChainManager();
				filterChainManager.getFilterChains().clear();
				shiroFilterFactoryBean.getFilterChainDefinitionMap().clear();
				this.dynamicFilterChain.clear();
				this.buildDynamicFilterChain();
				shiroFilterFactoryBean.setFilterChainDefinitionMap(this.getAllFilterChain());
				shiroFilterFactoryBean.getFilterChainDefinitionMap().forEach((k,v) -> filterChainManager.createChain(k, v));
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
	}
	
	private void buildDynamicFilterChain(){
		if(null == this.rulesProvider) return;
		List<RolePermRule> rolePermRules = this.rulesProvider.loadRolePermRules();
		if(null != rolePermRules)
			rolePermRules.forEach(rule -> {
				rule.setType(AuthorizeRule.RULE_TYPE_DEF);
				StringBuilder filterChain = rule.toFilterChain();
				if(null != filterChain){
					this.attachFilters(filterChain);
					this.dynamicFilterChain.putIfAbsent(rule.getUrl(), filterChain.toString());
				}
			}); 
		
		List<RolePermRule> hmacRules = this.rulesProvider.loadHmacRules();
		if(null != hmacRules)
			hmacRules.forEach(rule -> {
				rule.setType(AuthorizeRule.RULE_TYPE_HMAC);
				StringBuilder filterChain = rule.toFilterChain();
				if(null != filterChain)
					this.dynamicFilterChain.putIfAbsent(rule.getUrl(), filterChain.toString());
			}); 

		List<RolePermRule> jwtRules = this.rulesProvider.loadJwtRules();
		if(null != jwtRules)
			jwtRules.forEach(rule -> {
				rule.setType(AuthorizeRule.RULE_TYPE_JWT);
				StringBuilder filterChain = rule.toFilterChain();
				if(null != filterChain)
					this.dynamicFilterChain.putIfAbsent(rule.getUrl(), filterChain.toString());
			}); 
		
		List<CustomRule> customRules = this.rulesProvider.loadCustomRules();
		if(null != customRules)
			customRules.forEach(rule -> {
				rule.setType(AuthorizeRule.RULE_TYPE_CUSTOM);
				StringBuilder filterChain = rule.toFilterChain();
				if(null != filterChain){
					this.attachFilters(filterChain);
					this.dynamicFilterChain.putIfAbsent(rule.getUrl(), filterChain.toString());
				}
			});
	}
	
	private void attachFilters(StringBuilder filterChain){
		filterChain.append(","+Commons.FILTER_USER);
		if (this.properties.isKeepOneEnabled()) 
			filterChain.append(","+Commons.FILTER_KEEP_ONE);
		if (this.properties.isForceLogoutEnable()) 
			filterChain.append(","+Commons.FILTER_FORCE_LOGOUT);
	}
	
	public Map<String, Filter> getAllFilters() {
		Map<String, Filter> filters = Maps.newLinkedHashMap();
		filters.putAll(this.getStatefulFilters());
		filters.putAll(this.getStatelessFilters());
		return filters;
	}
	public Map<String, String> getAllFilterChain() {
		Map<String, String> allFilterChain = Maps.newLinkedHashMap();
		allFilterChain.putAll(this.getAnonFilterChain());
		allFilterChain.putAll(this.getDynamicFilterChain());
		allFilterChain.putAll(this.getStaticFilterChain());
		LOGGER.info("filterChains:"+allFilterChain);
		return allFilterChain;
	}


	public void setProperties(ShiroProperties properties) {
		this.properties = properties;
	}
	public void setSessionManager(DefaultWebSessionManager sessionManager) {
		this.sessionManager = sessionManager;
	}
	public void setCacheDelegator(CacheDelegator cacheDelegator) {
		this.cacheDelegator = cacheDelegator;
	}
	public String getLoginUrl() {
		return loginUrl;
	}
	public String getSuccessUrl() {
		return successUrl;
	}
	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}
	public void setAccountProvider(ShiroAccountProvider accountProvider) {
		this.accountProvider = accountProvider;
	}
	public void setRulesProvider(ShiroFilteRulesProvider rulesProvider) {
		this.rulesProvider = rulesProvider;
	}
	public void setCustomFilters(Map<String, Filter> customFilters) {
		this.customFilters = customFilters;
	}
	public Map<String, Filter> getStatefulFilters() {
		return statefulFilters;
	}
	public Map<String, Filter> getStatelessFilters() {
		return statelessFilters;
	}
	public Map<String, String> getAnonFilterChain() {
		return anonFilterChain;
	}
	public Map<String, String> getStaticFilterChain() {
		return staticFilterChain;
	}
	public Map<String, String> getDynamicFilterChain() {
		return dynamicFilterChain;
	}
	public void setMessages(MessageConfig messages) {
		this.messages = messages;
	}
}