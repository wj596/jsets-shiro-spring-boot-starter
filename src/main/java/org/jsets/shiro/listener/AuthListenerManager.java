package org.jsets.shiro.listener;

import java.util.Date;
import java.util.List;
import javax.servlet.ServletRequest;
import com.google.common.collect.Lists;

public class AuthListenerManager implements AuthListener{

	private final List<AuthListener> authListeners = Lists.newLinkedList();

	public void add(AuthListener listener) {
		this.authListeners.add(listener);
	}
	
	@Override
	public void onLoginSuccess(ServletRequest request, String account) {
		authListeners.forEach(t->{
			t.onLoginSuccess(request, account);
		});
	}

	@Override
	public void onLoginFailure(ServletRequest request, String account, String reason) {
		authListeners.forEach(t->{
			t.onLoginFailure(request, account ,reason);
		});
	}

	@Override
	public void onLogout(ServletRequest request, String account) {
		authListeners.forEach(t->{
			t.onLogout(request, account);
		});
	}

	@Override
	public void onKeepOneKickout(ServletRequest request, String account, String loginedHost, Date loginedTime) {
		authListeners.forEach(t->{
			t.onKeepOneKickout(request, account, loginedHost, loginedTime);
		});
	}

	@Override
	public void onForceLogout(ServletRequest request, String account) {
		authListeners.forEach(t->{
			t.onForceLogout(request, account);
		});
	}

	@Override
	public void onAccessAssert(ServletRequest request, String account, String roles, boolean allowed) {
		authListeners.forEach(t->{
			t.onAccessAssert(request, account, roles, allowed);
		});
	}

}
