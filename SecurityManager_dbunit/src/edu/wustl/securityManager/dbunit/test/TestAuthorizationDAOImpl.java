package edu.wustl.securityManager.dbunit.test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import junit.framework.TestCase;

import org.hibernate.SessionFactory;

import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.exception.SMTransactionException;
import edu.wustl.security.impl.AuthorizationDAOImpl;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.ISecurityManager;
import edu.wustl.security.manager.SecurityManager;
import edu.wustl.security.manager.SecurityManagerFactory;
import edu.wustl.security.privilege.PrivilegeUtility;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.dao.ProtectionElementSearchCriteria;
import gov.nih.nci.security.exceptions.CSConfigurationException;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.system.ApplicationSessionFactory;

public class TestAuthorizationDAOImpl extends TestCase{
	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	AuthorizationDAOImpl impl;
	private transient ISecurityManager securityManager = null;
	static String configFile = "";
	final private String ADMIN_GROUP = "ADMINISTRATOR_GROUP";
	final private String PUBLIC_GROUP = "PUBLIC_GROUP";
	public void setUp()
	{
		String ctxName = SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName();
		SessionFactory sFactory;
		try {
			System.setProperty("gov.nih.nci.security.configFile",configFile);
			sFactory = ApplicationSessionFactory
					.getSessionFactory(ctxName);
			impl = new AuthorizationDAOImpl(sFactory,ctxName);
			securityManager = SecurityManagerFactory.getSecurityManager(TestSecurityManager.class);
			
			
			removeAllUsers();
			insertSampleCSMUser();
			
			super.setUp();
			
		} catch (CSConfigurationException e) {
			e.printStackTrace();
		} catch (SMTransactionException e) {
			e.printStackTrace();
		} catch (SMException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
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
	 * Returns the user matching with the login name
	 * 
	 * @param loginName
	 *            name
	 * @return User
	 */
	private User getUserByLoginName(String loginName) {
		User user = null;
		try {
			user = securityManager.getUser(loginName);
		} catch (SMException e) {
			logger.error(e.getStackTrace());
		}
		return user;
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
		securityManager.createUser(user);
	}

	/**
	 * assigns the given group name to the user with the given login name
	 * 
	 * @param loginName
	 * @param groupName
	 * @throws SMException 
	 * @throws Exception
	 */
	private void assignGroupToUser(String loginName, String groupName) throws SMException
	{
		User user = securityManager.getUser(loginName);
		String userId = user.getUserId().toString();
		securityManager.assignUserToGroup(groupName, userId);
	}

	/**
	 * Removes all users from the system.
	 */
	private void removeAllUsers() {
		try {
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
	 * 
	 */
	public void testGetGroup()
	{
		try {
			assignGroupToUser("test", ADMIN_GROUP);
			assignGroupToUser("test", PUBLIC_GROUP);
			User user = getUserByLoginName("test");
			Set groups = impl.getGroups(user.getUserId().toString());
			assertEquals(2, groups.size());
		} catch (CSObjectNotFoundException e) {
			e.printStackTrace();
		} catch (SMException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 
	 */
	public void testGetPrivilegeMapForUser()
	{
		try {
			assignGroupToUser("test", ADMIN_GROUP);
			assignGroupToUser("test", PUBLIC_GROUP);
			User user = getUserByLoginName("test");
			PrivilegeUtility privilegeUtility = new PrivilegeUtility();
			ProtectionElement protectionElement = new ProtectionElement();
			protectionElement.setObjectId("edu.wustl.catissuecore.domain.User_1");
			ProtectionElementSearchCriteria protEleSearchCrit = new ProtectionElementSearchCriteria(
					protectionElement);
			List<ProtectionElement> list = privilegeUtility.getUserProvisioningManager().getObjects(protEleSearchCrit);
			System.out.println("list.size()" +list.size());
			for (ProtectionElement object : list) {
				System.out.println("getProtectionElementName "+object.getProtectionElementName());
				System.out.println("getProtectionElementId "+object.getProtectionElementId());
				System.out.println("getProtectionElementType "+object.getProtectionElementType());
			}
			List<ObjectPrivilegeMap> map = impl.getPrivilegeMap(user.getLoginName(),list);
			System.out.println("map"+map);
			for (ObjectPrivilegeMap objectPrivilegeMap : map) {
				System.out.println("getProtectionElement "+objectPrivilegeMap.getProtectionElement());
				System.out.println("Privileges().size() "+objectPrivilegeMap.getPrivileges().size());
				
			}
		}catch (SMException e) {
			e.printStackTrace();
		} catch (CSException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 
	 */
	public void testGetPrivilegeMapForSite()
	{
		try {
			assignGroupToUser("test", ADMIN_GROUP);
			assignGroupToUser("test", PUBLIC_GROUP);
			User user = getUserByLoginName("test");
			PrivilegeUtility privilegeUtility = new PrivilegeUtility();
			ProtectionElement protectionElement = new ProtectionElement();
			protectionElement.setObjectId("edu.wustl.catissuecore.domain.Site");
			ProtectionElementSearchCriteria protEleSearchCrit = new ProtectionElementSearchCriteria(
					protectionElement);
			List<ProtectionElement> list = privilegeUtility.getUserProvisioningManager().getObjects(protEleSearchCrit);
			System.out.println("list.size()" +list.size());
			for (ProtectionElement object : list) {
				System.out.println("getProtectionElementName "+object.getProtectionElementName());
				System.out.println("getProtectionElementId "+object.getProtectionElementId());
				System.out.println("getProtectionElementType "+object.getProtectionElementType());
			}
			List<ObjectPrivilegeMap> map = impl.getPrivilegeMap(user.getLoginName(),list);
			System.out.println("map"+map);
			for (ObjectPrivilegeMap objectPrivilegeMap : map) {
				System.out.println("getProtectionElement "+objectPrivilegeMap.getProtectionElement());
				System.out.println("Privileges().size() "+objectPrivilegeMap.getPrivileges().size());
				
			}
		}catch (SMException e) {
			e.printStackTrace();
		} catch (CSException e) {
			e.printStackTrace();
		}
	}
}