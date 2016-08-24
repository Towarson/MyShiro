package com.atguigu.shiro.services;

import java.util.Date;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Service;

@Service
public class ShiroService {

	//添加 shiro 的權限注解
	@RequiresRoles("admin")
	public void testMethod(){
		System.out.println("test method: " + new Date());
	}
	
}
