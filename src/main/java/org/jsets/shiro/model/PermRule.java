package org.jsets.shiro.model;

import java.io.Serializable;

public class PermRule implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private String url;// 资源URL
	private String needPerms;// 访问需要的权限列表(多个权限用逗号分开)
	
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public String getNeedPerms() {
		return needPerms;
	}
	public void setNeedPerms(String needPerms) {
		this.needPerms = needPerms;
	}

}
