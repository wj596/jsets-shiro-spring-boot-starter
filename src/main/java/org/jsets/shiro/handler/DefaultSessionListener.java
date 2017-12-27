package org.jsets.shiro.handler;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 默认SESSION监听
 */
public class DefaultSessionListener implements SessionListener {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultSessionListener.class);

    /**
     * 会话开始
     */
    @Override
    public void onStart(Session session) {
    	System.out.println("创建session:("+session.getId()+","+session.getHost()+")");
    	LOGGER.info("创建session:("+session.getId()+","+session.getHost()+")");
    }
    /**
     * 会话结束
     */
    @Override
    public void onStop(Session session) {
    	System.out.println("结束session:("+session.getId()+","+session.getHost()+")");
    	LOGGER.info("结束session:("+session.getId()+","+session.getHost()+")");
    }
    /**
     * 会话过期
     */
    @Override
    public void onExpiration(Session session) {
    	System.out.println("过期session:("+session.getId()+","+session.getHost()+")");
    	LOGGER.info("过期session:("+session.getId()+","+session.getHost()+")");
    }

}