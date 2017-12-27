package org.jsets.shiro.authc;

import java.util.ArrayList;
import java.util.Collection;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.CollectionUtils;

/**
 * 扩展自ModularRealmAuthenticator,认证开始先过滤掉不支持token类型的realm
 * 
 * @author wangjie (http://www.jianshu.com/u/ffa3cba4c604)
 * @date 2016年6月24日 下午2:55:15
 */
public class JsetsModularRealmAuthenticator extends ModularRealmAuthenticator {

	protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
		assertRealmsConfigured();
		Collection<Realm> realms = new ArrayList<>();
		for (Realm realm : getRealms()) {
			if (realm.supports(authenticationToken)) {
				realms.add(realm);
			}
		}
		if (CollectionUtils.isEmpty(realms)) {
			throw new IllegalStateException("Configuration error:  No realms support token type:" + authenticationToken.getClass());
		}
		if (realms.size() == 1) {
			return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
		} else {
			return doMultiRealmAuthentication(realms, authenticationToken);
		}
	}
	
}
