package edu.wustl.security.beans;


/**
 * A bean object to store role and group details.
 * @author deepti_shelar
 *
 */
public class RoleGroupDetailsBean {
	String roleName;
	String roleType;
	String groupType;
	String groupName;
	String roleId;
	String groupId;

	/**
	 * @return the roleName
	 */
	public String getRoleName() {
		return roleName;
	}
	/**
	 * @param roleName the roleName to set
	 */
	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}
	/**
	 * @return the roleType
	 */
	public String getRoleType() {
		return roleType;
	}
	/**
	 * @param roleType the roleType to set
	 */
	public void setRoleType(String roleType) {
		this.roleType = roleType;
	}
	/**
	 * @return the groupType
	 */
	public String getGroupType() {
		return groupType;
	}
	/**
	 * @param groupType the groupType to set
	 */
	public void setGroupType(String groupType) {
		this.groupType = groupType;
	}
	/**
	 * @return the groupName
	 */
	public String getGroupName() {
		return groupName;
	}
	/**
	 * @param groupName the groupName to set
	 */
	public void setGroupName(String groupName) {
		this.groupName = groupName;
	}
	/**
	 * @return the roleId
	 */
	public String getRoleId() {
		return roleId;
	}
	/**
	 * @param roleId the roleId to set
	 */
	public void setRoleId(String roleId) {
		this.roleId = roleId;
	}
	/**
	 * @return the groupId
	 */
	public String getGroupId() {
		return groupId;
	}
	/**
	 * @param groupId the groupId to set
	 */
	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}
	/**
	 * @param obj the object to be compared.
	 * @return true if any of the following attributes of both object matches:
	 * 			- roleId
	 *          - roleName
	 *          - groupName
	 *          - groupId
	 *          - roleType
	 *          - groupType
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object object)
	{
		boolean equals = false;
		if((object!=null) && object instanceof RoleGroupDetailsBean)
		{
			RoleGroupDetailsBean bean = (RoleGroupDetailsBean)object;
			if(
				bean.getGroupId() != null ? bean.getGroupId().equals(this.getGroupId()) : false ||
				bean.getGroupName() != null ? bean.getGroupName().equals(this.getGroupName()) : false ||
				bean.getGroupType() != null ? bean.getGroupType().equals(this.getGroupType()) : false ||
				bean.getRoleId() != null ? bean.getRoleId().equals(this.getRoleId()) : false ||
				bean.getRoleName() != null ? bean.getRoleName().equals(this.getRoleName()) : false ||
				bean.getRoleType() != null ? bean.getRoleType().equals(this.getRoleType()) : false)
			{
				return true;
			}
		}
		return equals;
	}
	/**
	 * 
	 */
	public int hashCode()
	{
		int hashCode = 0;
		return hashCode;
	}
	/**
	 * 
	 */
	public String toString()
	{
		return "groupId=" + this.getGroupId()+ ":\n" + 
		"groupName=" + this.getGroupName() +":\n" +
		"groupType=" + this.getGroupType() +":\n" +
		"roleId=" + this.getRoleId() +":\n"+
		"roleName=" + this.getRoleName() +":\n"+
		"roleType=" + this.getRoleType();
	}
}
