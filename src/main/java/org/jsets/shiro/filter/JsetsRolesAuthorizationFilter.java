package org.jsets.shiro.filter;

import java.io.IOException;
import java.util.List;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;

/**
 * 重写RolesAuthorizationFilter，使其继承自JsetsAuthorizationFilter;
 * <br>修改了匹配逻辑，只要当前用户有一个角色满足URL所需角色就放行
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604) 
 * @date 2016年6月24日 下午2:55:15
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
