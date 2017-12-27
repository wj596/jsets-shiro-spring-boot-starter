package org.jsets.shiro.config;

public class IllegalConfigException extends RuntimeException{

	private static final long serialVersionUID = -3380352624906053051L;

	public IllegalConfigException() {
        super();
    }

    public IllegalConfigException(String s) {
        super(s);
    }

    public IllegalConfigException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalConfigException(Throwable cause) {
        super(cause);
    }


}
