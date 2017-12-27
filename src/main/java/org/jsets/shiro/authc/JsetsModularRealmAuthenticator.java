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
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
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
