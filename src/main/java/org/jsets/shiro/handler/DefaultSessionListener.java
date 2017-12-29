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
package org.jsets.shiro.handler;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 默认SESSION监听
 * 
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class DefaultSessionListener implements SessionListener {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultSessionListener.class);

    /**
     * 会话开始
     */
    @Override
    public void onStart(Session session) {
    	LOGGER.info("创建session:("+session.getId()+","+session.getHost()+")");
    }
    /**
     * 会话结束
     */
    @Override
    public void onStop(Session session) {
    	LOGGER.info("结束session:("+session.getId()+","+session.getHost()+")");
    }
    /**
     * 会话过期
     */
    @Override
    public void onExpiration(Session session) {
    	LOGGER.info("过期session:("+session.getId()+","+session.getHost()+")");
    }

}