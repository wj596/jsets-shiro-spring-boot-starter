package org.jsets.shiro.realm;

import org.jsets.shiro.model.Account;

public abstract class StatelessThreadContext {

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