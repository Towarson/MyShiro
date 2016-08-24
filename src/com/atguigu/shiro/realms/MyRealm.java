package com.atguigu.shiro.realms;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm{
	
	
	/**
	 * 关于授权
	 * 1. 需要在 shiro 的配置文件中配置哪些資源需要受保護. 
	 * 2. 當訪問受保護的資源時, shiro 會囘調該方法. 
	 */
	@Override//AuthenticationInfo doGetAuthenticationInfo
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		//1. 從 PrincipalCollection 中獲取登錄用戶的信息. 即獲取 doGetAuthenticationInfo
		//方法返回值的 principal
		Object principal = principals.getPrimaryPrincipal();
		
		//2. 若 principal 是一個實體類, 則其中可能會包含其所有的權限信息. 若沒有權限信息, 則需要使用 principal
		//來調用數據庫, 查詢其權限信息
		Set<String> roles = new HashSet<>();
		roles.add("user");
		if("admin".equals(principal)) {
			roles.add("admin");
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(roles);
		//3. 把權限信息封裝到 SimpleAuthorizationInfo 中并返回
		return info;
	}
	
	/**
	 * 该方法是认证(即登录)时的回调方法
	 * 1. 正常登錄, 走 SpringMVC 的 handler 方法
	 * 2. handler 方法中的登錄邏輯需要參照 Quickstart 中的代碼.
	 * 3. 參數 AuthenticationToken 即為 Handler 方法中调用 Subject 的 login(UsernamePasswordToken) 方法是傳入的參數
	 * 
	 * 關於 MD5 鹽值加密:
	 * 1. 需要配置 Realm 的 credentialsMatcher 屬性
	 * 2. doGetAuthenticationInfo 的返回值為 SimpleAuthenticationInfo. 但需要使用
	 * SimpleAuthenticationInfo.SimpleAuthenticationInfo(Object principal, 
	 * 	Object hashedCredentials, ByteSource credentialsSalt, String realmName)
	 * 構造器.
	 * 3. 如何來計算加密后的密碼:
	 * SimpleHash.SimpleHash(String algorithmName, Object source, Object salt, int hashIterations) 	
	 **/
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		
		//1. 把 AuthenticationToken 強轉為 UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		
		//2. 從 UsernamePasswordToken 中獲取 username
		String username = upToken.getUsername();
		
		//3. 調用 Service 或 Dao 方法利用 username 來獲取數據表中當前用戶的信息
		System.out.println("调用数据库的方法来获取[" + username + "]对应的记录进行验证");
		if("unknown".equals(username)) {
			throw new UnknownAccountException("用户不存在！！！");
		} 
		
		//4. 把從數據庫中獲取的用戶的信息封裝為 SimpleAuthenticationInfo 對象并返回
		//principal: 登錄的實體信息. 可以是 username, 也可以是一個對象. 
		Object principal = username;
		
		//當前 Realm 的 name. 直接調用父類的 getName() 方法即可
		String realmName = getName();
		SimpleAuthenticationInfo info = null;
//		info = new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		
		//MD5盐值加密,盐值加密后的密码
		Object hashedCredentials = null;
		if("user".equals(username)) {
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		}else if("admin".equals(username)) {
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		
		//盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		info = new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		
		return info;
	}
	
	public static void main(String[] args) {
		String algorithmName = "MD5";
		String source = "123456";
		ByteSource salt = ByteSource.Util.bytes("admin");
		int iterations = 1024;
		Object result = new SimpleHash(algorithmName, source, salt, iterations);
		System.out.println(result);
	}


}
