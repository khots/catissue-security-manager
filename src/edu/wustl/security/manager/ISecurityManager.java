package edu.wustl.security.manager;

import java.util.List;
import java.util.Set;

import edu.wustl.common.beans.NameValueBean;
import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.security.exceptions.SMTransactionException;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;
/**
 * Interface for SecurityManager.
 * @author deepti_shelar
 *
 */
public interface ISecurityManager {
	
	//public UserProvisioningManager getUserProvisioningManager() throws CSException;
	public boolean login(String loginName, String password) throws SMException;
	public void createUser(User user) throws SMTransactionException;
	public User getUser(String loginName) throws SMException;
	public void removeUser(String userId) throws SMException;
	public List<Role> getRoles() throws SMException;
	public void assignRoleToUser(String userID, String roleID) throws SMException;
	public String getGroupIdForRole(String roleID);
	public Role getUserRole(long userID) throws SMException;
	public String getUserGroup(long userID) throws SMException;
	public void modifyUser(User user) throws SMException;
	public User getUserById(String userId) throws SMException;
	public List getUsers() throws SMException;
	//public List getObjects(SearchCriteria searchCriteria) throws SMException, CSException;
	public void removeUserFromGroup(String userGroupname, String userId) throws SMException;
	public void assignUserToGroup(String userGroupname, String userId) throws SMException;
	public void assignAdditionalGroupsToUser(String userId, String[] groupIds) throws SMException;
	public boolean isAuthorized(String userName, String objectId, String privilegeName)
	throws SMException;
	public boolean checkPermission(String userName, String objectType, String objectIdentifier,
			String privilegeName) throws SMException;
	public String getProtectionGroupByName(AbstractDomainObject obj, String nameConsistingOf)
	throws SMException;
	public String[] getProtectionGroupByName(AbstractDomainObject obj) throws SMException;
	public List<NameValueBean> getPrivilegesForAssignPrivilege(String roleName);
	public Set<NameValueBean> getObjectsForAssignPrivilege(String userID, String[] objectTypes,
			String[] privilegeNames) throws SMException;
	//public AuthorizationManager getAuthorizationManager() throws CSException;
}
