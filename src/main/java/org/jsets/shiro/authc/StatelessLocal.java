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

import org.jsets.shiro.model.Account;

/**
 * 无状态验证本地缓存
 * <br>由于无SESSION,账号信息缓存于此供应用使用
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public abstract class StatelessLocal {

    private static final ThreadLocal<Account> ACCOUNTS = new ThreadLocal<Account>();

    public static Account getAccount() {
    	return ACCOUNTS.get();
    }

    protected static void setAccount(Account account) {
    	ACCOUNTS.set(account);
    }

    protected static void removeAccount() {
    	ACCOUNTS.remove();
    }
}