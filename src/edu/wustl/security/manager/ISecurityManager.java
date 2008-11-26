
package edu.wustl.security.manager;

import java.util.List;

import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.security.exception.SMException;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;

/**
 * Interface for SecurityManager.
 * @author deepti_shelar
 */
public interface ISecurityManager
{

	// UserProvisioningManager getUserProvisioningManager() throws CSException;
	/**
	 * 
	 */
	boolean login(String loginName, String password) throws SMException;

	void createUser(User user) throws SMException;

	User getUser(String loginName) throws SMException;

	void removeUser(String userId) throws SMException;

	List<Role> getRoles() throws SMException;

	void assignRoleToUser(String userID, String roleID) throws SMException;

	String getGroupIdForRole(String roleID);

	Role getUserRole(long userID) throws SMException;

	String getRoleName(long userID) throws SMException;

	void modifyUser(User user) throws SMException;

	User getUserById(String userId) throws SMException;

	List<User> getUsers() throws SMException;

	// List getObjects(SearchCriteria searchCriteria) throws SMException, CSException;
	void removeUserFromGroup(String userGroupname, String userId) throws SMException;

	void assignUserToGroup(String userGroupname, String userId) throws SMException;

	void assignAdditionalGroupsToUser(String userId, String[] groupIds) throws SMException;

	/* boolean isAuthorized(String userName, String objectId, String privilegeName)
	 throws SMException;*/
	/* boolean checkPermission(String userName, String objectType, String objectIdentifier,
			String privilegeName) throws SMException;
	*/
	/* String getProtectionGroupByName(AbstractDomainObject obj, String nameConsistingOf)
	 throws SMException;
	*/String[] getProtectionGroupByName(AbstractDomainObject obj) throws SMException;
	// List<NameValueBean> getPrivilegesForAssignPrivilege(String roleName); : Not used anymore , shd be removed as AssignPrivilege in suite is removed
	// Set<NameValueBean> getObjectsForAssignPrivilege(String userID, String[] objectTypes,
	//	String[] privilegeNames) throws SMException;
	// AuthorizationManager getAuthorizationManager() throws CSException;
}
