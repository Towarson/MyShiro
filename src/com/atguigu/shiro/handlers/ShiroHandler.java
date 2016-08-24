package com.atguigu.shiro.handlers;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.atguigu.shiro.services.ShiroService;

@RequestMapping("/shiro")
@Controller
public class ShiroHandler {
	
	@Autowired
	private ShiroService service;
	
	public String test() {
		System.out.println(service.getClass().getName());
		service.testMethod();
		System.out.println("哥们是来找事的！！就是要搞个大冲突！");
		System.out.println("啊！听说要有冲突发生！！");
		System.out.println("哥们是来解决冲突的！");
		System.out.println("我是在本地更新！");
		System.out.println("我是另一个程序员的说！");
		return "success";
	}
	
	@RequestMapping("/login")
	public String login(@RequestParam("username") String username,
			@RequestParam("password") String password) {
		
		// 1. 获取当前用户. 直接调用 SecurityUtils.getSubject() 方法. 
		Subject currentUser = SecurityUtils.getSubject();
		
		// 2. 检验用户是否已经被认证. 即用户是否已经登录. 调用 Subject 的 isAuthenticated()
		if(!currentUser.isAuthenticated()) {
			//3. 若没有登录, 则把用户名和密码封装为一个 UsernamePasswordToken 对象
			UsernamePasswordToken token = new UsernamePasswordToken(username, password);
			token.setRememberMe(true);
			try {
				// 4.执行登录. 调用 Subject 的 login(UsernamePasswordToken) 方法
				currentUser.login(token);
			} catch (AuthenticationException ae) {
				//5. 认证失败可能抛出的所有的异常都是 AuthenticationException 异常或 AuthenticationException 异常的子类. 
				System.out.println("登录失败:" + ae.getMessage());
				return "redirect:/login.jsp";
			}
		}
		return "success";
	}
}
