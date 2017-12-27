package org.jsets.shiro.model;

public class DefaultAccount implements Account{

	private static final long serialVersionUID = 4329526398056888883L;
	
	private String account;
	private String password;
	
	public DefaultAccount(String account,String password){
		this.account = account;
		this.password = password;
	}

	public String getAccount() {
		return account;
	}
	public void setAccount(String account) {
		this.account = account;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
}