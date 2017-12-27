package org.jsets.shiro.model;

import java.io.Serializable;

/**
 * 基于角色的过滤规则
 * @author wangjie
 *
 */
public class RoleRule implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private String url;// 资源URL
	private String needRoles;// 访问需要的角色列表(多个角色用逗号分开)
	
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
}