/**
 *<p>Title: </p>
 *<p>Description:  </p>
 *<p>Copyright: (c) Washington University, School of Medicine 2004</p>
 *<p>Company: Washington University, School of Medicine, St. Louis.</p>
 *@author Aarti Sharma
 *@version 1.0
 */

package edu.wustl.common.security;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import edu.wustl.common.beans.NameValueBean;
import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.common.query.AbstractClient;
import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.security.exceptions.SMTransactionException;
import edu.wustl.common.util.Permissions;
import edu.wustl.common.util.Roles;
import edu.wustl.common.util.XMLPropertyHandler;
import edu.wustl.common.util.dbmanager.DBUtil;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.global.TextConstants;
import edu.wustl.common.util.logger.Logger;
import gov.nih.nci.security.AuthenticationManager;
import gov.nih.nci.security.AuthorizationManager;
import gov.nih.nci.security.SecurityServiceProvider;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroup;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.dao.GroupSearchCriteria;
import gov.nih.nci.security.dao.ProtectionElementSearchCriteria;
import gov.nih.nci.security.dao.RoleSearchCriteria;
import gov.nih.nci.security.dao.SearchCriteria;
import gov.nih.nci.security.dao.UserSearchCriteria;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.exceptions.CSTransactionException;

/**
 * <p>
 * Title:
 * </p>
 * <p>
 * Description:
 * </p>
 * <p>
 * Copyright: (c) Washington University, School of Medicine 2005
 * </p>
 * <p>
 * Company: Washington University, School of Medicine, St. Louis.
 * </p>
 * 
 * @author Aarti Sharma
 * @version 1.0
 */

public class SecurityManager implements Permissions
{

	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	private static AuthenticationManager authenticationManager = null;

	private static AuthorizationManager authorizationManager = null;

	private Class requestingClass = null;
	public static boolean initialized = false;
	public static String APPLICATION_CONTEXT_NAME = null;

	public static HashMap<String, String> rolegroupNamevsId = new HashMap<String, String>();

	public static final String ADMINISTRATOR_GROUP = "ADMINISTRATOR_GROUP";
	public static final String SUPER_ADMINISTRATOR_GROUP = "SUPER_ADMINISTRATOR_GROUP";
	public static final String SUPERVISOR_GROUP = "SUPERVISOR_GROUP";
	public static final String TECHNICIAN_GROUP = "TECHNICIAN_GROUP";
	public static final String PUBLIC_GROUP = "PUBLIC_GROUP";

	public static final String CLASS_NAME = "CLASS_NAME";

	public static final String TABLE_NAME = "TABLE_NAME";

	public static final String TABLE_ALIAS_NAME = "TABLE_ALIAS_NAME";

	protected static String securityDataPrefix = CLASS_NAME;

	private static Properties SECURITY_MANAGER_PROP;

	static{
		InputStream inputStream = DBUtil.class.getClassLoader().getResourceAsStream(
				Constants.SECURITY_MANAGER_PROP_FILE);
		SECURITY_MANAGER_PROP = new Properties();
		try
		{
			SECURITY_MANAGER_PROP.load(inputStream);
			inputStream.close();
		}
		catch (IOException exception)
		{
			logger.warn("Not able to initialize Security Manager Properties.", exception);
		}
	}

	/**
	 * @param class1
	 */
	public SecurityManager(Class class1)
	{
		super();
		requestingClass = class1;
		if (!initialized)
		{
			getApplicationContextName();
			initializeConstants();
		}
	}

	/**
	 * @param class1
	 * @return
	 */
	public static final SecurityManager getInstance(Class class1)
	{
		Class className = null;
		SecurityManager securityManager=null;
		try
		{
			String securityManagerClass=SECURITY_MANAGER_PROP.getProperty(Constants.SECURITY_MANAGER_CLASSNAME);
			if (securityManagerClass != null)
			{
				className = Class.forName(securityManagerClass);
			}
			if (className != null)
			{
				Constructor[] cons = className.getConstructors();
				securityManager= (SecurityManager) cons[0].newInstance(class1);
			}
		}
		catch (Exception exception)
		{
			logger.warn("Error in creating SecurityManager instance",exception);
		}

		if(null==securityManager)
		{
			securityManager= new SecurityManager(class1);
		}
		return securityManager;
	}

	public static String getApplicationContextName()
	{
		String applicationName = "";
		try
		{
			applicationName = SECURITY_MANAGER_PROP.getProperty(Constants.APPLN_CONTEXT_NAME);
			APPLICATION_CONTEXT_NAME = applicationName;
		}
		catch (Exception exception)
		{
			logger.warn("Error in getting application context name",exception);
		}

		return applicationName;
	}

	/**
	* Returns group id from Group name
	* @param groupName
	* @return
	* @throws CSException 
	* @throws SMException 
	*/
	private String getGroupID(String groupName) throws CSException, SMException
	{
		List list;
		String groupId=null;
		Group group = new Group();
		group.setGroupName(groupName);
		UserProvisioningManager userProvisioningManager=getUserProvisioningManager();
		SearchCriteria searchCriteria = new GroupSearchCriteria(group);
		group.setApplication(userProvisioningManager.getApplication(APPLICATION_CONTEXT_NAME));
		list = getObjects(searchCriteria);
		if (!list.isEmpty())
		{
			group = (Group) list.get(0);
			groupId= group.getGroupId().toString();
		}

		return groupId;
	}

	/**
	 * Returns role id from role name
	 * @param roleName
	 * @return
	 */
	private String getRoleID(String roleName) throws CSException, SMException
	{
		String roleId=null;
		Role role = new Role();
		role.setName(roleName);
		SearchCriteria searchCriteria = new RoleSearchCriteria(role);
		UserProvisioningManager userProvisioningManager= getUserProvisioningManager();
		role.setApplication(userProvisioningManager.getApplication(APPLICATION_CONTEXT_NAME));
		List list = getObjects(searchCriteria);
		if (!list.isEmpty())
		{
			role = (Role) list.get(0);
			roleId=role.getId().toString();
		}
		return roleId;
	}

	private void initializeConstants()
	{
		try
		{
			rolegroupNamevsId.put(Constants.ADMINISTRATOR_ROLE,
					getRoleID(Constants.ROLE_ADMINISTRATOR));
			rolegroupNamevsId.put(Constants.PUBLIC_ROLE, getRoleID(Constants.SCIENTIST));
			rolegroupNamevsId.put(Constants.TECHNICIAN_ROLE, getRoleID(Constants.TECHNICIAN));
			rolegroupNamevsId.put(Constants.SUPERVISOR_ROLE, getRoleID(Constants.SUPERVISOR));
			rolegroupNamevsId.put(Constants.ADMINISTRATOR_GROUP_ID, getGroupID(ADMINISTRATOR_GROUP));
			rolegroupNamevsId.put(Constants.PUBLIC_GROUP_ID, getGroupID(PUBLIC_GROUP));
			rolegroupNamevsId.put(Constants.TECHNICIAN_GROUP_ID, getGroupID(TECHNICIAN_GROUP));
			rolegroupNamevsId.put(Constants.SUPERVISOR_GROUP_ID, getGroupID(SUPERVISOR_GROUP));
			rolegroupNamevsId.put(Constants.SUPER_ADMINISTRATOR_ROLE,
					getRoleID(Constants.ROLE_SUPER_ADMINISTRATOR));
			rolegroupNamevsId.put(Constants.SUPER_ADMINISTRATOR_GROUP_ID,
					getRoleID(SUPER_ADMINISTRATOR_GROUP));
			initialized = true;
		}
		catch (CSException exception)
		{
			logger.warn("Error in initializing rolegroupNamevsId map",exception);
		}
		catch (SMException exception)
		{
			logger.warn("Error in initializing rolegroupNamevsId map",exception);
		}
	}

	/**
	 * Returns the AuthenticationManager for the caTISSUE Core. This method
	 * follows the singleton pattern so that only one AuthenticationManager is
	 * created for the caTISSUE Core.
	 *
	 * @return
	 * @throws	CSException
	 */
	protected AuthenticationManager getAuthenticationManager() throws CSException
	{
		if (authenticationManager == null)
		{
			authenticationManager = SecurityServiceProvider
					.getAuthenticationManager(APPLICATION_CONTEXT_NAME);
		}
		return authenticationManager;
	}

	/**
	 * Returns the Authorization Manager for the caTISSUE Core. This method
	 * follows the singleton pattern so that only one AuthorizationManager is
	 * created.
	 *
	 * @return
	 * @throws	CSException
	 */
	protected AuthorizationManager getAuthorizationManager() throws CSException
	{

		if (authorizationManager == null)
		{
			authorizationManager = SecurityServiceProvider
					.getAuthorizationManager(APPLICATION_CONTEXT_NAME);
		}

		return authorizationManager;
	}

	/**
	 * Returns the UserProvisioningManager singleton object.
	 *
	 * @return
	 * @throws	CSException
	 */
	public UserProvisioningManager getUserProvisioningManager() throws CSException
	{
		return (UserProvisioningManager) getAuthorizationManager();
	}

	/**
	 * Returns true or false depending on the person gets authenticated or not.
	 * @param requestingClass
	 * @param loginName login name
	 * @param password password
	 * @return
	 * @throws CSException
	 */
	public boolean login(String loginName, String password) throws SMException
	{
		boolean loginSuccess = false;
		try
		{
			AuthenticationManager authMngr = getAuthenticationManager();
			loginSuccess = authMngr.login(loginName, password);
		}
		catch (CSException exception)
		{
			StringBuffer mesg=new StringBuffer("Authentication fails for user")
				.append(loginName).append("requestingClass:").append(requestingClass);
			logger.debug(mesg.toString());
			throw new SMException(mesg.toString(), exception);
		}
		return loginSuccess;
	}

	/**
	 * This method creates a new User in the database based on the data passed
	 * 
	 * @param user
	 *            user to be created
	 * @throws SMTransactionException
	 *             If there is any exception in creating the User
	 */
	public void createUser(User user) throws SMTransactionException
	{
		try
		{
			getUserProvisioningManager().createUser(user);
		}
		catch (CSTransactionException exception)
		{
			logger.debug("Unable to create user "+user.getEmailId());
			throw new SMTransactionException(exception.getMessage(), exception);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to create user:"+user.getEmailId(), exception);
		}
	}

	/**
	 * This method returns the User object from the database for the passed
	 * User's Login Name. If no User is found then null is returned
	 *
	 * @param loginName
	 *            Login name of the user
	 * @return @throws
	 *         SMException
	 */
	public User getUser(String loginName) throws SMException
	{
		try
		{
			return getAuthorizationManager().getUser(loginName);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get user: "+loginName,exception);
			throw new SMException("Unable to get user: "+loginName, exception);
		}
	}

	/**
	 * This method returns array of CSM user id of all users who are administrators
	 * @return
	 * @throws SMException
	 */
	public Long[] getAllAdministrators() throws SMException
	{
		Long[] userId;
		try
		{
			Group group = new Group();
			group.setGroupName(ADMINISTRATOR_GROUP);
			GroupSearchCriteria groupSearchCriteria = new GroupSearchCriteria(group);
			List list = getObjects(groupSearchCriteria);
			group = (Group) list.get(0);
			Set<User> users = group.getUsers();
			userId = new Long[users.size()];
			Iterator<User> iterator = users.iterator();
			for (int i = 0; i < users.size(); i++)
			{
				userId[i] = ((User) iterator.next()).getUserId();
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get users: Exception: " + exception.getMessage());
			throw new SMException(exception.getMessage(), exception);
		}
		return userId;
	}

	/**
	 * This method checks whether a user exists in the database or not
	 *
	 * @param loginName
	 *            Login name of the user
	 * @return TRUE is returned if a user exists else FALSE is returned
	 * @throws SMException
	 */
	public boolean userExists(String loginName) throws SMException
	{
		boolean userExists = true;
		try
		{
			if (getUser(loginName) == null)
			{
				userExists = false;
			}
		}
		catch (SMException exception)
		{
			logger.debug("Unable to get user :"+loginName);
			throw exception;
		}
		return userExists;
	}

	public void removeUser(String userId) throws SMException
	{
		try
		{
			getUserProvisioningManager().removeUser(userId);
		}
		catch (CSTransactionException ex)
		{
			logger.debug("Unable to get user: Exception: " + ex.getMessage());
			throw new SMTransactionException("Failed to find this user with userId:" + userId, ex);
		}
		catch (CSException e)
		{
			logger.debug("Unable to obtain Authorization Manager: Exception: " + e.getMessage());
			throw new SMException("Failed to find this user with userId:" + userId, e);
		}
	}

	/**
	 * This method returns Vactor of all the role objects defined for the
	 * application from the database
	 * 
	 * @return @throws
	 *         SMException
	 */
	public List<Role> getRoles() throws SMException
	{
		List<Role> roles = new ArrayList();
		UserProvisioningManager userProvisioningManager = null;
		try
		{
			userProvisioningManager = getUserProvisioningManager();
			roles.add(userProvisioningManager.getRoleById(rolegroupNamevsId
					.get(Constants.SUPER_ADMINISTRATOR_ROLE)));
			roles.add(userProvisioningManager.getRoleById(rolegroupNamevsId
					.get(Constants.ADMINISTRATOR_ROLE)));
			roles.add(userProvisioningManager.getRoleById(rolegroupNamevsId
					.get(Constants.SUPERVISOR_ROLE)));
			roles.add(userProvisioningManager.getRoleById(rolegroupNamevsId
					.get(Constants.TECHNICIAN_ROLE)));
			roles.add(userProvisioningManager.getRoleById(rolegroupNamevsId
					.get(Constants.PUBLIC_ROLE)));

		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: ",exception);
			throw new SMException(exception.getMessage(), exception);
		}
		return roles;
	}

	/**
	 * Assigns a Role to a User
	 * 
	 * @param userName - the User Name to to whom the Role will be assigned
	 * @param roleID -	The id of the Role which is to be assigned to the user
	 * @throws SMException
	 */
	public void assignRoleToUser(String userID, String roleID) throws SMException
	{
		UserProvisioningManager userProvisioningManager = null;
		User user;
		String groupId;
		try
		{
			userProvisioningManager = getUserProvisioningManager();
			user = userProvisioningManager.getUserById(userID);

			//Remove user from any other role if he is assigned some
			userProvisioningManager.removeUserFromGroup(rolegroupNamevsId
					.get(Constants.ADMINISTRATOR_GROUP_ID), String.valueOf(user.getUserId()));
			userProvisioningManager.removeUserFromGroup(rolegroupNamevsId
					.get(Constants.SUPERVISOR_GROUP_ID), String.valueOf(user.getUserId()));
			userProvisioningManager.removeUserFromGroup(rolegroupNamevsId
					.get(Constants.TECHNICIAN_GROUP_ID), String.valueOf(user.getUserId()));
			userProvisioningManager.removeUserFromGroup(rolegroupNamevsId
					.get(Constants.PUBLIC_GROUP_ID), String.valueOf(user.getUserId()));

			//Add user to corresponding group
			groupId = getGroupIdForRole(roleID);
			if (groupId == null)
			{
				logger.info(" User assigned no role");
			}
			else
			{
				assignAdditionalGroupsToUser(String.valueOf(user.getUserId()),
						new String[]{groupId});
				logger.info(" User assigned role:" + groupId);
			}

		}
		catch (CSException exception)
		{
			logger.debug("UNABLE TO ASSIGN ROLE TO USER: Exception: " + exception.getMessage());
			throw new SMException(exception.getMessage(), exception);
		}
	}

	public String getGroupIdForRole(String roleID)
	{
		String roleName=null;
		String roleId=null;
		String roleGroupId=null;
		if (roleID.equals(rolegroupNamevsId.get(Constants.ADMINISTRATOR_ROLE)))
		{
			roleName=Constants.ADMINISTRATOR_ROLE;
			roleId=Constants.ADMINISTRATOR_GROUP_ID;
		}
		else if (roleID.equals(rolegroupNamevsId.get(Constants.SUPERVISOR_ROLE)))
		{
			roleName=Constants.SUPERVISOR_ROLE;
			roleId=Constants.SUPERVISOR_GROUP_ID;
		}
		else if (roleID.equals(rolegroupNamevsId.get(Constants.TECHNICIAN_ROLE)))
		{
			roleName=Constants.TECHNICIAN_ROLE;
			roleId=Constants.TECHNICIAN_GROUP_ID;
		}
		else if (roleID.equals(rolegroupNamevsId.get(Constants.PUBLIC_ROLE)))
		{
			roleName=Constants.PUBLIC_ROLE;
			roleId=Constants.PUBLIC_GROUP_ID;
		}
		else
		{
			logger.debug("role corresponds to no group");
		}
		if(roleId!=null)
		{
			roleGroupId=rolegroupNamevsId.get(roleId);
			logger.info("role corresponds to "+roleName);
		}
		return roleGroupId;
	}

	public Role getUserRole(long userID) throws SMException
	{
		Set<Group> groups;
		UserProvisioningManager userProvisioningManager = null;
		Role role = null;
		try
		{
			userProvisioningManager = getUserProvisioningManager();
			groups = userProvisioningManager.getGroups(String.valueOf(userID));
			role = getRole(groups, userProvisioningManager);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: " + exception.getMessage(),exception);
			throw new SMException(exception.getMessage(), exception);
		}
		return role;
	}

	/**
	 * @param groups
	 * @param userProvisioningManager
	 * @param role
	 * @return
	 * @throws CSObjectNotFoundException
	 */
	private Role getRole(Set groups, UserProvisioningManager userProvisioningManager)
			throws CSObjectNotFoundException
	{
		Role role = null;
		Group group;
		Iterator<Group> it = groups.iterator();
		while (it.hasNext())
		{
			group = (Group) it.next();
			if (group.getApplication().getApplicationName().equals(APPLICATION_CONTEXT_NAME))
			{
				if (group.getGroupName().equals(ADMINISTRATOR_GROUP))
				{
					role = userProvisioningManager.getRoleById(rolegroupNamevsId
							.get(Constants.ADMINISTRATOR_ROLE));
					break;
				}
				else if (group.getGroupName().equals(SUPERVISOR_GROUP))
				{
					role = userProvisioningManager.getRoleById(rolegroupNamevsId
							.get(Constants.SUPERVISOR_ROLE));
					break;
				}
				else if (group.getGroupName().equals(TECHNICIAN_GROUP))
				{
					role = userProvisioningManager.getRoleById(rolegroupNamevsId
							.get(Constants.TECHNICIAN_ROLE));
					break;
				}
				else if (group.getGroupName().equals(PUBLIC_GROUP))
				{
					role = userProvisioningManager.getRoleById(rolegroupNamevsId
							.get(Constants.PUBLIC_ROLE));
					break;
				}
			}
		}
		return role;
	}

	/**
	 * Name : Virender Mehta
	 * Reviewer: Sachin Lale
	 * Bug ID: 3842
	 * Patch ID: 3842_2
	 * See also: 3842_1
	 * Description: This function will return the Role name(Administrator, Scientist, Technician, Supervisor )
	 * @param userID
	 * @return Role Name
	 * @throws SMException
	 */
	public String getUserGroup(long userID) throws SMException
	{
		String role=TextConstants.EMPTY_STRING;
		Set groups;
		UserProvisioningManager userProvisioningManager = null;
		Iterator it;
		Group group;
		try
		{
			userProvisioningManager = getUserProvisioningManager();
			groups = userProvisioningManager.getGroups(String.valueOf(userID));
			it = groups.iterator();
			while (it.hasNext())
			{
				group = (Group) it.next();
				if (group.getApplication().getApplicationName().equals(APPLICATION_CONTEXT_NAME))
				{
					if (group.getGroupName().equals(ADMINISTRATOR_GROUP))
					{
						role=Roles.ADMINISTRATOR;
						break;
					}
					else if (group.getGroupName().equals(SUPERVISOR_GROUP))
					{
						role=Roles.SUPERVISOR;
						break;
					}
					else if (group.getGroupName().equals(TECHNICIAN_GROUP))
					{
						role=Roles.TECHNICIAN;
						break;
					}
					else if (group.getGroupName().equals(PUBLIC_GROUP))
					{
						role=Roles.SCIENTIST;
						break;
					}
				}
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: " + exception.getMessage(),exception);
			throw new SMException(exception.getMessage(), exception);
		}
		return role;
	}

	/**
	 * Modifies an entry for an existing User in the database based on the data
	 * passed.
	 *
	 * @param user -the User object that needs to be modified in the database
	 * @throws SMException if there is any exception in modifying the User in the database
	 */
	public void modifyUser(User user) throws SMException
	{
		try
		{
			getUserProvisioningManager().modifyUser(user);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to modify user: Exception: " + exception.getMessage(),exception);
			throw new SMException(exception.getMessage(), exception);
		}
	}

	/**
	 * Returns the User object for the passed User id.
	 *
	 * @param userId -The id of the User object which is to be obtained
	 * @return The User object from the database for the passed User id
	 * @throws SMException -if the User object is not found for the given id
	 */
	public User getUserById(String userId) throws SMException
	{
		try
		{
			return getUserProvisioningManager().getUserById(userId);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get user by Id for : "+userId,exception);
			throw new SMException(exception.getMessage(), exception);
		}
	}

	/**
	 * Returns list of the User objects for the passed email address.
	 *
	 * @param emailAddress -Email Address for which users need to be searched
	 * @return List Returns list of the User objects for the passed email address.
	 * @throws SMException if there is any exception while querying the database
	 */
	public List getUsersByEmail(String emailAddress) throws SMException
	{
		try
		{
			User user = new User();
			user.setEmailId(emailAddress);
			SearchCriteria searchCriteria = new UserSearchCriteria(user);
			return getUserProvisioningManager().getObjects(searchCriteria);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get users by emailAddress for email:"+emailAddress,exception);
			throw new SMException(exception.getMessage(), exception);
		}
	}

	/**
	 * @throws SMException
	 *  
	 */
	public List getUsers() throws SMException
	{
		try
		{
			User user = new User();
			SearchCriteria searchCriteria = new UserSearchCriteria(user);
			return getUserProvisioningManager().getObjects(searchCriteria);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get all users: Exception: " + exception.getMessage());
			throw new SMException(exception.getMessage(), exception);
		}
	}

	/**
	 * Returns list of objects corresponding to the searchCriteria passed.
	 * @param searchCriteria
	 * @return List of resultant objects
	 * @throws SMException if searchCriteria passed is null or if search results in no results
	 * @throws CSException
	 */
	public List getObjects(SearchCriteria searchCriteria) throws SMException, CSException
	{
		if (null == searchCriteria)
		{
			logger.debug("searchCriteria is null");
			throw new SMException("Null Parameters passed");
		}
		UserProvisioningManager userProvisioningManager = getUserProvisioningManager();
		List list = userProvisioningManager.getObjects(searchCriteria);
		if (null == list || list.size() <= 0)
		{
			logger.warn("Search resulted in no results");
		}
		return list;
	}

	public void assignUserToGroup(String userGroupname, String userId) throws SMException
	{
		if (userId == null || userGroupname == null)
		{
			logger.debug(" Null or insufficient Parameters passed");
			throw new SMException("Null or insufficient Parameters passed");
		}

		try
		{
			Group group = getUserGroup(userGroupname);
			if (group == null)
			{
				logger.debug("No user group with name " + userGroupname + " is present");
			}
			else
			{
				String[] groupIds = {group.getGroupId().toString()};
				assignAdditionalGroupsToUser(userId, groupIds);
			}
		}
		catch (CSException exception)
		{
			String mess="The Security Service encountered a fatal exception.";
			logger.fatal(mess, exception);
			throw new SMException(mess, exception);
		}
	}

	public void removeUserFromGroup(String userGroupname, String userId) throws SMException
	{
		if (userId == null || userGroupname == null)
		{
			logger.debug(" Null or insufficient Parameters passed");
			throw new SMException("Null or insufficient Parameters passed");
		}

		try
		{
			UserProvisioningManager userProvisioningManager = getUserProvisioningManager();
			Group group = getUserGroup(userGroupname);
			if (group != null)
			{
				userProvisioningManager.removeUserFromGroup(group.getGroupId().toString(), userId);
			}
			else
			{
				logger.debug("No user group with name " + userGroupname + " is present");
			}
		}
		catch (CSException ex)
		{
			String mess="The Security Service encountered a fatal exception.";
			logger.fatal(mess, ex);
			throw new SMException(mess, ex);
		}
	}

	/**
	 * @param userGroupname
	 * @return
	 * @throws SMException
	 * @throws CSException
	 */
	private Group getUserGroup(String userGroupname) throws SMException, CSException
	{
		Group group = new Group();
		group.setGroupName(userGroupname);
		SearchCriteria searchCriteria = new GroupSearchCriteria(group);
		List list = getObjects(searchCriteria);
		if (list.isEmpty())
		{
			group=null;
		}
		else
		{
			group = (Group) list.get(0);
		}

		return group;
	}

	public void assignAdditionalGroupsToUser(String userId, String[] groupIds) throws SMException
	{
		if (userId == null || groupIds == null || groupIds.length < 1)
		{
			String mesg=" Null or insufficient Parameters passed";
			logger.debug(mesg);
			throw new SMException(mesg);
		}
		Set consolidatedGroupIds = new HashSet();
		Set consolidatedGroups;
		String[] finalUserGroupIds;
		UserProvisioningManager userProvisioningManager;
		Group group = null;
		try
		{
			userProvisioningManager = getUserProvisioningManager();
			consolidatedGroups = userProvisioningManager.getGroups(userId);
			if (null != consolidatedGroups)
			{
				Iterator it = consolidatedGroups.iterator();
				while (it.hasNext())
				{
					group = (Group) it.next();
					consolidatedGroupIds.add(String.valueOf(group.getGroupId()));
				}
			}
			 //Consolidating all the Groups
			for (int i = 0; i < groupIds.length; i++)
			{
				consolidatedGroupIds.add(groupIds[i]);
			}
			finalUserGroupIds = new String[consolidatedGroupIds.size()];
			Iterator it = consolidatedGroupIds.iterator();
			for (int i = 0; it.hasNext(); i++)
			{
				finalUserGroupIds[i] = (String) it.next();
			}
			 //Setting groups for user and updating it
			userProvisioningManager.assignGroupsToUser(userId, finalUserGroupIds);
		}
		catch (CSException exception)
		{
			String mesg="The Security Service encountered a fatal exception.";
			logger.fatal(mesg, exception);
			throw new SMException(mesg, exception);
		}
	}

	public boolean isAuthorized(String userName, String objectId, String privilegeName)
			throws SMException
	{
		try
		{
			return getAuthorizationManager().checkPermission(userName, objectId,privilegeName);
		}
		catch (CSException e)
		{
			logger.debug( e.getMessage(),e);
			throw new SMException(e.getMessage(), e);
		}
	}

	public boolean checkPermission(String userName, String objectType, String objectIdentifier,
			String privilegeName) throws SMException
	{
		boolean isAuthorized=true;
		if (Boolean.parseBoolean(XMLPropertyHandler.getValue(Constants.ISCHECKPERMISSION)))
		{
			try
			{
				isAuthorized = getAuthorizationManager().checkPermission(userName,
						objectType + "_" + objectIdentifier, privilegeName);
			}
			catch (CSException exception)
			{
				logger.debug("Unable tocheck permissionn" ,exception);
				throw new SMException("Unable to check permission",exception);
			}
		}
		return isAuthorized;
	}

	/**
	 * This method returns name of the Protection groupwhich consists of obj as
	 * Protection Element and whose name consists of string nameConsistingOf.
	 * 
	 * @param obj
	 * @param nameConsistingOf
	 * @return @throws
	 *         SMException
	 */
	public String getProtectionGroupByName(AbstractDomainObject obj, String nameConsistingOf)
			throws SMException
	{
		Set protectionGroups;
		ProtectionGroup protectionGroup;
		ProtectionElement protectionElement;
		String name = null;
		String protectionElementName = obj.getObjectId();
		try
		{
			AuthorizationManager authManager = getAuthorizationManager();
			protectionElement = authManager.getProtectionElement(protectionElementName);
			protectionGroups = authManager.getProtectionGroups(protectionElement
					.getProtectionElementId().toString());
			Iterator<ProtectionGroup> it = protectionGroups.iterator();
			while (it.hasNext())
			{
				protectionGroup = (ProtectionGroup) it.next();
				name = protectionGroup.getProtectionGroupName();
				if (name.indexOf(nameConsistingOf) != -1)
				{
					break;
				}
			}
		}
		catch (CSException exception)
		{
			String mess= new StringBuffer("Unable to get protection group by name")
								.append(nameConsistingOf).append(" for Protection Element ")
								.append(protectionElementName).toString();
			logger.debug(mess, exception);
			throw new SMException(mess,exception);
		}
		return name;

	}

	/**
	 * This method returns name of the Protection groupwhich consists of obj as
	 * Protection Element and whose name consists of string nameConsistingOf.
	 * 
	 * @param obj
	 * @param nameConsistingOf
	 * @return @throws SMException
	 */
	public String[] getProtectionGroupByName(AbstractDomainObject obj) throws SMException
	{
		Set protectionGroups;
		Iterator it;
		ProtectionGroup protectionGroup;
		ProtectionElement protectionElement;
		String[] names = null;
		String protectionElementName = obj.getObjectId();
		try
		{
			AuthorizationManager authManager = getAuthorizationManager();
			protectionElement = authManager.getProtectionElement(protectionElementName);
			protectionGroups = authManager.getProtectionGroups(protectionElement
					.getProtectionElementId().toString());
			it = protectionGroups.iterator();
			names = new String[protectionGroups.size()];
			int i = 0;
			while (it.hasNext())
			{
				protectionGroup = (ProtectionGroup) it.next();
				names[i++] = protectionGroup.getProtectionGroupName();

			}
		}
		catch (CSException exception)
		{
			String mess="Unable to get protection group for Protection Element "+ protectionElementName;
			logger.debug(mess,exception);
			throw new SMException(mess, exception);
		}
		return names;

	}

	/**
	 * Returns name value beans corresponding to all privileges that can be
	 * assigned for Assign Privileges Page.
	 * 
	 * @param roleName role name of user logged in
	 * @return
	 *//*
	public List<NameValueBean> getPrivilegesForAssignPrivilege(String roleName)
	{
		List<NameValueBean> privileges = new Vector();
		NameValueBean nameValueBean;
		nameValueBean = new NameValueBean(Permissions.READ, Permissions.READ);
		privileges.add(nameValueBean);
		//Use privilege only provided to Administrtor in Assing privileges page.
		if (roleName.equals(Constants.ADMINISTRATOR))
		{
			nameValueBean = new NameValueBean(Permissions.USE, Permissions.USE);
			privileges.add(nameValueBean);
		}
		return privileges;
	}*/

	/**
	 * This method returns NameValueBeans for all the objects of type objectType
	 * on which user with identifier userID has privilege ASSIGN_ <
	 * <privilegeName>>.
	 * 
	 * @param userID
	 * @param objectType
	 * @param privilegeName
	 * @return @throws
	 *         SMException thrown if any error occurs while retreiving
	 *         ProtectionElementPrivilegeContextForUser
	 */
	private Set<NameValueBean> getObjectsForAssignPrivilege(Collection privilegeMap, String objectType,
			String privilegeName) throws SMException
	{
		Set<NameValueBean> objects = new HashSet<NameValueBean>();
		NameValueBean nameValueBean;
		ObjectPrivilegeMap objectPrivilegeMap;
		Collection privileges;
		Iterator iterator;
		String objectId;
		Privilege privilege;

		if (privilegeMap != null)
		{
			iterator = privilegeMap.iterator();
			while (iterator.hasNext())
			{
				objectPrivilegeMap = (ObjectPrivilegeMap) iterator.next();
				objectId = objectPrivilegeMap.getProtectionElement().getObjectId();
				if (objectId.indexOf(objectType + "_") != -1)
				{
					privileges = objectPrivilegeMap.getPrivileges();
					Iterator it = privileges.iterator();
					String name;
					while (it.hasNext())
					{
						privilege = (Privilege) it.next();
						if (privilege.getName().equals("ASSIGN_" + privilegeName))
						{
							name=objectId.substring(objectId.lastIndexOf('_') + 1);
							nameValueBean = new NameValueBean(name,name);
							objects.add(nameValueBean);
							break;
						}
					}
				}
			}
		}

		return objects;
	}

	/**
	 * This method returns name value beans of the object ids for types
	 * identified by objectTypes on which user can assign privileges identified
	 * by privilegeNames User needs to have ASSIGN_ {privilegeName}privilege
	 * on these objects to assign corresponding privilege on them identified by
	 * userID has.
	 *
	 * @param userID
	 * @param objectTypes
	 * @param privilegeNames
	 * @return @throws SMException
	 */
	public Set<NameValueBean> getObjectsForAssignPrivilege(String userID, String[] objectTypes,
			String[] privilegeNames) throws SMException
	{
		Set<NameValueBean> objects=null;

		try
		{
			User user = new User();
			user = getUserById(userID);
			if (objectTypes == null || privilegeNames == null ||user == null)
			{
				logger.debug(" User not found");
				objects = new HashSet<NameValueBean>();
			}
			else
			{
				objects=getAssignedPrivilege(objectTypes, privilegeNames, user);
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get objects: " ,exception);
			throw new SMException("Unable to get objects: ", exception);
		}
		return objects;

	}

	/**
	 * @param objectTypes
	 * @param privilegeNames
	 * @param objects
	 * @param user
	 * @throws CSException
	 */
	private Set<NameValueBean> getAssignedPrivilege(String[] objectTypes, String[] privilegeNames,
			User user) throws CSException
	{
		Set<NameValueBean> objects = new HashSet<NameValueBean>();
		Collection privilegeMap;
		List list;
		ProtectionElement protectionElement;
		ProtectionElementSearchCriteria protectionElementSearchCriteria;
		AuthorizationManager authorizationManager = getAuthorizationManager();
		for (int i = 0; i < objectTypes.length; i++)
		{
			for (int j = 0; j < privilegeNames.length; j++)
			{
				try
				{
					protectionElement = new ProtectionElement();
					protectionElement.setObjectId(objectTypes[i] + "_*");
					protectionElementSearchCriteria=new ProtectionElementSearchCriteria(protectionElement);
					list = getObjects(protectionElementSearchCriteria);
					privilegeMap=authorizationManager.getPrivilegeMap(user.getLoginName(),list);
					for (int k = 0; k < list.size(); k++)
					{
						protectionElement = (ProtectionElement) list.get(k);
					}

					objects.addAll(getObjectsForAssignPrivilege(privilegeMap, objectTypes[i],
							privilegeNames[j]));
				}
				catch (SMException smex)
				{
					logger.debug(" Exception in getting object of privileges", smex);
				}
			}
		}
		return objects;
	}

	

	/**
	 * Checks whether an object type has any identified data associated with
	 * it or not.
	 * @param aliasName
	 * @return
	 */
	protected boolean hasAssociatedIdentifiedData(String aliasName)
	{
		boolean hasIdentifiedData = false;
		List identifiedData = new ArrayList();
		identifiedData = (List) AbstractClient.identifiedDataMap.get(aliasName);
		if (identifiedData != null)
		{
			hasIdentifiedData = true;
		}
		return hasIdentifiedData;
	}

	public static String getSecurityDataPrefix()
	{
		return securityDataPrefix;
	}

	public static void setSecurityDataPrefix(String securityDataPrefix)
	{
		SecurityManager.securityDataPrefix = securityDataPrefix;
	}

	/**
	 * Description: This method checks user's privilege on identified data.
	 * Name : Aarti Sharma
	 * Reviewer: Sachin Lale
	 * Bug ID: 4111
	 * Patch ID: 4111_2
	 * See also: 4111_1
	 * @param userId User's Identifier
	 * @return true if user has privilege on identified data else false
	 * @throws SMException
	 */
	public boolean hasIdentifiedDataAccess(Long userId) throws SMException
	{
		boolean hasIdentifiedDataAccess = false;
		try
		{
			//Get user's role
			Role role = getUserRole(userId.longValue());
			UserProvisioningManager userProvisioningManager = getUserProvisioningManager();

			//Get privileges the user has based on his role
			Set<Privilege> privileges = userProvisioningManager.getPrivileges(String.valueOf(role.getId()));
			Iterator<Privilege> privIterator = privileges.iterator();
			Privilege privilege;

			// If user has Identified data access set hasIdentifiedDataAccess true
			for (int i = 0; i < privileges.size(); i++)
			{
				privilege = (Privilege) privIterator.next();
				if (privilege.getName().equals(Permissions.IDENTIFIED_DATA_ACCESS))
				{
					hasIdentifiedDataAccess = true;
					break;
				}
			}
		}
		catch (CSException exception)
		{
			logger.debug("Exception in hasIdentifiedDataAccess method",exception);
			throw new SMException(exception.getMessage(), exception);
		}
		return hasIdentifiedDataAccess;

	}
}
