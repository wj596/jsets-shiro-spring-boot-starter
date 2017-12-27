package org.jsets.shiro.model;

import java.io.Serializable;

public class JwtRule implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private String url;// 资源URL
	private String needRoles;// 访问需要的角色列表(多个角色用逗号分开，不需要角色验证此项为空)
	private String needPerms;// 访问需要的权限列表(多个权限用逗号分开，不需要权限验证此项为空)
	
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public String getNeedRoles() {
		return needRoles;
	}
	public void setNeedRoles(String needRoles) {
		this.needRoles = needRoles;
	}
	public String getNeedPerms() {
		return needPerms;
	}
	public void setNeedPerms(String needPerms) {
		this.needPerms = needPerms;
	}
}