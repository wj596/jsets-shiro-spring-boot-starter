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

import java.io.IOException;
import java.util.List;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;

import com.google.common.collect.Lists;

/**
 * 重写RolesAuthorizationFilter，使其继承自JsetsAuthorizationFilter;
 * <br>修改了匹配逻辑，只要当前用户有一个角色满足URL所需角色就放行
 * 
 * author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JsetsRolesAuthorizationFilter extends JsetsAuthorizationFilter{

    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
    	Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) {
        	return true;
        }
        List<String> roles = CollectionUtils.asList(rolesArray);
        boolean[] hasRoles = subject.hasRoles(roles);
        for(boolean hasRole:hasRoles){
        	if(hasRole) return true;
        }
        return false;
    }
}
