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
package org.jsets.shiro.config;


import java.util.Map;
import javax.servlet.Filter;
import org.jsets.shiro.service.ShiroFilteRulesProvider;
import com.google.common.collect.Maps;

/**
 * 过滤器链应用端配置
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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