package edu.wustl.securityManager.dbunit.test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import junit.framework.TestCase;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.exception.SMTransactionException;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.ISecurityManager;
import edu.wustl.security.manager.SecurityManager;
import edu.wustl.security.manager.SecurityManagerFactory;
import edu.wustl.security.privilege.PrivilegeCache;
import edu.wustl.security.privilege.PrivilegeManager;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.system.applicationservice.ApplicationService;
import gov.nih.nci.system.applicationservice.ApplicationServiceProvider;
import gov.nih.nci.system.comm.client.ClientSession;

public class TestPrivilegeManager extends TestCase{
	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);
	static ApplicationService appService = null;
	PrivilegeManager privManager;
	static String configFile = "";
	protected void setUp() throws Exception {
		
		privManager = PrivilegeManager.getInstance();
		System.setProperty("gov.nih.nci.security.configFile",configFile);
		removeAllUsers();
		insertSampleCSMUser();

		System.setProperty("javax.net.ssl.trustStore", "E://jboss-4.2.2.GA//server//default//conf//chap8.keystore");
		appService = ApplicationServiceProvider.getApplicationService();
		ClientSession cs = ClientSession.getInstance();
		try
		{ 
		//	cs.startSession("test", "test");
		} 	
		catch (Exception ex) 
		{ 
			System.out.println(ex.getMessage()); 
			ex.printStackTrace();
			fail();
			System.exit(1);
		}		
		super.setUp();
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
	 * Removes all users from the system.
	 */
	private void removeAllUsers() {
		try {
			ISecurityManager securityManager = SecurityManagerFactory.getSecurityManager(null);
			List<User> allUsers = securityManager.getUsers();
			for (User user : allUsers) {
				Long userId = user.getUserId();
				securityManager.removeUser(userId.toString());
			}
		} catch (Exception e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * Inserts a sample User.
	 * @throws SMTransactionException 
	 * 
	 * @throws Exception
	 */
	private void insertSampleCSMUser() throws SMTransactionException {
		User user = new User();
		String newVal = "test";
		user.setDepartment(newVal);
		user.setEmailId(newVal + "@test.com");
		user.setFirstName(newVal);
		user.setLoginName(newVal);
		user.setOrganization(newVal);
		user.setPassword(newVal);
		user.setTitle(newVal);
		user.setLastName(newVal);
		ISecurityManager securityManager;
		try {
			securityManager = SecurityManagerFactory.getSecurityManager(null);
			securityManager.createUser(user);
		} catch (SMException e) {
			e.printStackTrace();
		}
	}
	/**
	 * testGetClasses
	 */
	public void testGetClasses()
	{
		List<String> classes = privManager.getClasses();
		assertNotNull(classes);
	}
	/**
	 * testGetLazyObjects
	 */
	public void testGetLazyObjects()
	{
		List<String> classes = privManager.getLazyObjects();
		assertEquals(0, classes.size());
	}
	/**
	 * testEagerObjects
	 */
	public void testEagerObjects()
	{
		List<String> classes = privManager.getEagerObjects();
		assertNotNull(classes);
	}
	/**
	 * testGetAccesibleUsers
	 */
	public void testGetAccesibleUsers()
	{
		String objectId = "edu.wustl.catissuecore.domain.Participant";
		String privilege = "QUERY";
		Set<String> classes;
		try {
			classes =  privManager.getAccesibleUsers(objectId, privilege);
			System.out.println("classes.size()  "+classes.size());
			assertNotNull(classes);
		} catch (CSException e) {
			logger.error(e.getStackTrace());
			e.printStackTrace();
		}
	}
	/**
	 * getPrivilegeCaches
	 */
	public void testGetPrivilegeCaches()
	{
		Collection<PrivilegeCache> classes = privManager.getPrivilegeCaches();
		System.out.println("classes.size()  "+classes.size());
		assertNotNull(classes);
	}
	/**
	 * testGetPrivilegeCacheLoginName
	 */
	public void testGetPrivilegeCacheLoginName()
	{
		PrivilegeCache privilegeCache = privManager.getPrivilegeCache("test");
		System.out.println("privilegeCache   "+privilegeCache.getLoginName());
		assertNotNull(privilegeCache);
		assertEquals("test", privilegeCache.getLoginName());
	}
	/**
	 * testGetPrivilegeCacheLoginName
	 */
	public void testRemovePrivilegeCache()
	{
		User user;
		try {
			user = SecurityManagerFactory.getSecurityManager(null).getUser("test");
			privManager.removePrivilegeCache(user.getUserId().toString());
			PrivilegeCache privilegeCache = privManager.getPrivilegeCache("test");
			//assertNull(privilegeCache);
		} catch (SMException e) {
			e.printStackTrace();
		}
	}
	/**
	 * getPrivilegeCaches
	 *//*
	public void testHasGroupPrivilege()
	{
		String roleId = "1";
		String objectId = "edu.wustl.catissuecore.domain.Participant";
		String privilegeName = "QUERY";
		boolean hasPriv;
		try
		{
			hasPriv = privManager.hasGroupPrivilege(roleId, objectId, privilegeName);
			System.out.println("hasPriv  "+hasPriv);
			assertNotNull(hasPriv);
		}
		catch (CSObjectNotFoundException e)
		{
			e.printStackTrace();
		}
		catch (CSException e)
		{
			e.printStackTrace();
		}
	}*/
}
