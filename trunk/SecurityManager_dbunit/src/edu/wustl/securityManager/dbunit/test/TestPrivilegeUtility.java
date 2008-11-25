package edu.wustl.securityManager.dbunit.test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.beans.SecurityDataBean;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.exception.SMTransactionException;
import edu.wustl.security.global.Roles;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.ISecurityManager;
import edu.wustl.security.manager.SecurityManager;
import edu.wustl.security.manager.SecurityManagerFactory;
import edu.wustl.security.privilege.PrivilegeUtility;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.Application;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroup;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.dao.RoleSearchCriteria;
import gov.nih.nci.security.exceptions.CSException;

public class TestPrivilegeUtility extends TestCase {
	
	PrivilegeUtility privilegeUtility;
	final private String ADMIN_GROUP = "ADMINISTRATOR_GROUP";
	static String configFile = "";
	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	public void setUp() throws Exception
	{
		privilegeUtility = new PrivilegeUtility();
		System.setProperty("gov.nih.nci.security.configFile",configFile);
	}
	static
	{
		Properties SECURITY_MANAGER_PROP;
		InputStream inputStream = SecurityManagerPropertiesLocator.class.getClassLoader().getResourceAsStream(
		"smDBUnit.properties");
		SECURITY_MANAGER_PROP = new Properties();
		try
		{
			SECURITY_MANAGER_PROP.load(inputStream);
			inputStream.close();
			configFile = SECURITY_MANAGER_PROP.getProperty("gov.nih.nci.security.configFile");
		}
		catch (IOException exception)
		{
			logger.error(exception.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetRole()
	{
		String roleName = "Administrator";
		try {
			Role role = privilegeUtility.getRole(roleName);
			assertEquals("Administrator", role.getName());
			assertEquals("1", role.getId().toString());
			
		} catch (SMException e) {
			logger.error(e.getStackTrace());
		} catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetRoleByPrivilege()
	{
		String privName = "READ";
		try {
			Role role = privilegeUtility.getRoleByPrivilege(privName);
			assertEquals("READ_DENIED", role.getName());
			assertEquals("10", role.getId().toString());
			
		} catch (SMException e) {
			logger.error(e.getStackTrace());
		} catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetRolePrivileges()
	{
		String roleId = "1";
		try {
			Set<Privilege> rolePrivileges = privilegeUtility.getRolePrivileges(roleId);
			assertEquals(24, rolePrivileges.size());
		} catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetUserProvisioningManager()
	{
		try {
			UserProvisioningManager upManager = privilegeUtility.getUserProvisioningManager();
			assertNotNull(upManager);
		} catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetUserById()
	{
		removeAllUsers();
		insertSampleCSMUser();
		try {
			ISecurityManager securityManager = SecurityManagerFactory.getSecurityManager();
			List<User> allUsers = securityManager.getUsers();
			for (User user : allUsers) {
				Long userId = user.getUserId();
				User user1 = privilegeUtility.getUserById(userId.toString());
				assertNotNull(user1);
				assertEquals("test", user1.getLastName());
			}
		}catch (SMException e) {
				logger.error(e.getStackTrace());
			}finally{
				removeAllUsers();
			}
		}
	/**
	 * 
	 */
	public void testGetUser()
	{
		removeAllUsers();
		insertSampleCSMUser();
		try {
			User user1 = privilegeUtility.getUser("test");
			assertNotNull(user1);
			assertEquals("test", user1.getLastName());
		}catch (SMException e) {
			logger.error(e.getStackTrace());
		}finally{
			removeAllUsers();
		}
	}
	/**
	 * 
	 */
	public void testGetProtectionGroup ()
	{
		try {
			ProtectionGroup protectionGroup = privilegeUtility.
			getProtectionGroup("ADMINISTRATOR_PROTECTION_GROUP");
			assertNotNull(protectionGroup );
			assertEquals("ADMINISTRATOR_PROTECTION_GROUP", protectionGroup .getProtectionGroupName());
		}catch (CSException e) {
			logger.error(e.getStackTrace());
		}catch (SMException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetGroupIdForRole()
	{
		String grpId = privilegeUtility.getGroupIdForRole("1");
		assertNotNull(grpId);
		assertEquals("1",grpId);
	}
	/**
	 * 
	 */
	public void testGetObjects()
	{
		Role role = new Role();
		role.setName("");
		RoleSearchCriteria criteria = new RoleSearchCriteria(role);
		List<Role> list;
		try {
			list = privilegeUtility.getObjects(criteria);
			for (Role role1 : list) {
				System.out.println("getName() "+role1.getName());
			}
			assertNotNull(list);
		} catch (SMException e) {
			e.printStackTrace();
		} catch (CSException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 
	 */
	public void testGetObjectsNull()
	{
		Role role = new Role();
		role.setName("");
		List<Role> list;
		try {
			list = privilegeUtility.getObjects(null);
			for (Role role1 : list) {
				System.out.println("getName() "+role1.getName());
			}
			assertNotNull(list);
		} catch (SMException e) {
			e.printStackTrace();
		} catch (CSException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 
	 */
	public void testGetPrivilegeById ()
	{
		try {
			Privilege priv = privilegeUtility.getPrivilegeById("1");
			assertNotNull(priv);
			assertEquals("CREATE", priv.getName());
		}catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testAssignAdditionalGroupsToUser()
	{
		removeAllUsers();
		insertSampleCSMUser();
		try {
			String[] groupIds = {"3","4"};
			ISecurityManager securityManager = SecurityManagerFactory.getSecurityManager();
			User user = securityManager.getUser("test");
			privilegeUtility.assignAdditionalGroupsToUser(user.getUserId().toString(), groupIds);
			/*Set<Group> groups = user.getGroups();
			for (Group object : groups) {
				System.out.println(object.getGroupName());
			}*/
		}catch (SMException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 */
	public void testGetApplication()
	{
		try {
			Application application = privilegeUtility.getApplication("catissuecore");
			assertNotNull(application);
			assertEquals("catissuecore", application.getApplicationName());
		}catch (CSException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * 
	 *//*
	public void testInsertAuthorizationData()
	{
		try {
			edu.wustl.catissuecore.domain.User user = new edu.wustl.catissuecore.domain.User();
			
			List<SecurityDataBean> authorizationData = new ArrayList<SecurityDataBean>();
			Set protectionObjects=new HashSet();
			protectionObjects.add(user);
			String[] dynamicGroups;
			privilegeUtility.insertAuthorizationData
			(authorizationData, protectionObjects, null);
		}catch (SMException e) {
			logger.error(e.getStackTrace());
		}
	}*/
	/**
	 * Inserts a sample User.
	 * @throws SMTransactionException 
	 * 
	 * @throws Exception
	 */
	private void insertSampleCSMUser() {
		User user = new User();
		String newVal = "test" ;
		user.setDepartment(newVal);
		user.setEmailId(newVal + "@test.com");
		user.setFirstName(newVal);
		user.setLoginName(newVal);
		user.setOrganization(newVal);
		user.setPassword(newVal);
		user.setTitle(newVal);
		user.setLastName(newVal);
		try {
			SecurityManagerFactory.getSecurityManager().createUser(user);
		} catch (SMException e) {
			e.printStackTrace();
		}
	}
	/**
	 * Removes all users from the system.
	 */
	private void removeAllUsers() {
		try {
			ISecurityManager securityManager = SecurityManagerFactory.getSecurityManager();
			List<User> allUsers = securityManager.getUsers();
			for (User user : allUsers) {
				Long userId = user.getUserId();
				securityManager.removeUser(userId.toString());
			}
		} catch (Exception e) {
			logger.error(e.getStackTrace());
		}
	}
	public void testInsertAuthData()
	{
		Vector authorizationData = new Vector();
		Set group = new HashSet();
		String userId = "";
		ISecurityManager securityManager;
		try
		{
			securityManager = SecurityManagerFactory.getSecurityManager();
			List<User> allUsers = securityManager.getUsers();
			for (User user1 : allUsers) {
				Long userId1 = user1.getUserId();
				group.add(user1);
			}
			// Protection group of PI
			SecurityDataBean userGroupRoleProtectionGroupBean;
			userGroupRoleProtectionGroupBean = new SecurityDataBean();
			userGroupRoleProtectionGroupBean.setUser(userId);
			userGroupRoleProtectionGroupBean.setRoleName(Roles.UPDATE_ONLY);
			userGroupRoleProtectionGroupBean.setGroupName(ADMIN_GROUP);
			userGroupRoleProtectionGroupBean.setGroup(group);
			authorizationData.add(userGroupRoleProtectionGroupBean);
			PrivilegeUtility util = new PrivilegeUtility();
			Set protectionObjects=new HashSet();
			edu.wustl.catissuecore.domain.User usr = new edu.wustl.catissuecore.domain.User();
			protectionObjects.add(usr);
			util.insertAuthorizationData(authorizationData, protectionObjects, null);
		}
		catch (SMException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
