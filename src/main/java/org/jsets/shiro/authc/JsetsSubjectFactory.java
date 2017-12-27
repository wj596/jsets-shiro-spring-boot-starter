package org.jsets.shiro.authc;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.jsets.shiro.util.Commons;

/**
 * 扩展自DefaultWebSubjectFactory,对于无状态的TOKEN不创建session
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class JsetsSubjectFactory extends DefaultWebSubjectFactory { 
	
	private final DefaultSessionStorageEvaluator storageEvaluator;
	
	/**
	 * DefaultSessionStorageEvaluator是否持久化SESSION的开关 
	 */
	public JsetsSubjectFactory(DefaultSessionStorageEvaluator storageEvaluator){
		this.storageEvaluator = storageEvaluator;
	}
	
    public Subject createSubject(SubjectContext context) { 
    	this.storageEvaluator.setSessionStorageEnabled(Boolean.TRUE);
    	AuthenticationToken token = context.getAuthenticationToken();
    	if(Commons.isStatelessToken(token)){
    		System.out.println("non session");
            // 不创建 session 
            context.setSessionCreationEnabled(false);
            // 不持久化session
            this.storageEvaluator.setSessionStorageEnabled(Boolean.FALSE);
    	}
        return super.createSubject(context); 
    }
    
}