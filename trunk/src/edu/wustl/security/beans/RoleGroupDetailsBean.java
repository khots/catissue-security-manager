package edu.wustl.security.beans;



/**
 * A bean object to store role and group details.
 * @author deepti_shelar
 *
 */
public class RoleGroupDetailsBean {
	private String roleName;
	private String roleType;
	private String groupType;
	private String groupName;
	private String roleId;
	private String groupId;

	/**
	 * @return the roleName
	 */
	public String getRoleName() {
		return roleName;
	}
	/**
	 * @param roleName the roleName to set
	 */
	public void setRoleName(final String roleName) {
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
	public void setRoleType(final String roleType) {
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
	public void setGroupType(final String groupType) {
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
	public void setGroupName(final String groupName) {
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
	public void setRoleId(final String roleId) {
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
	public void setGroupId(final String groupId) {
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
	public boolean equals(final Object object)
	{
		boolean equals = false;
		if((object!=null) && object instanceof RoleGroupDetailsBean)
		{
			RoleGroupDetailsBean bean = (RoleGroupDetailsBean)object;
			if(
				isObjectEqual(bean.getGroupId(),this.getGroupId()) ||
				isObjectEqual(bean.getGroupName(),this.getGroupName()) ||
				isObjectEqual(bean.getGroupType(),this.getGroupType()) ||
				isObjectEqual(bean.getRoleId(),this.getRoleId()) ||
				isObjectEqual(bean.getRoleName(),this.getRoleName()) ||
				isObjectEqual(bean.getRoleType(),this.getRoleType())
				)
			{
				equals = true;
			}
		}
		return equals;
	}
	
	private boolean isObjectEqual(final Object src,final  Object target)
	{
		return (src == null ? false : src.equals(target));
	}
	/**
	 * 
	 *//*
	public int hashCode()
	{
		int hashCode = 0;
		if(this.groupId != null)
		{
			hashCode = this.groupId.hashCode();
		} else if(this.groupName != null)
		{
			hashCode = this.groupName.hashCode();
		} else if(this.groupType != null)
		{
			hashCode = this.groupType.hashCode();
		} else if(this.roleId != null)
		{
			hashCode = this.roleId.hashCode();
		} else if(this.roleName != null)
		{
			hashCode = this.roleName.hashCode();
		} else if(this.roleType != null)
		{
			hashCode = this.roleType.hashCode();
		} 
		return hashCode;
	}*/
	public int hashCode()
	{
		/*int hash = 7;
		hash = 31 * hash + (null == roleId ? 0 : roleId.hashCode());
		hash = 31 * hash + (null == roleName ? 0 : roleName.hashCode());
		hash = 31 * hash + (null == roleType ? 0 : roleType.hashCode());
		hash = 31 * hash + (null == groupId ? 0 : groupId.hashCode());
		hash = 31 * hash + (null == groupName ? 0 : groupName.hashCode());
		hash = 31 * hash + (null == groupType ? 0 : groupType.hashCode());
		return hash;*/
		return 1;
	}
	/**
	 * 
	 */
	public String toString()
	{
		return "groupId=" + this.getGroupId()+ ":" + 
		"groupName=" + this.getGroupName() +":" +
		"groupType=" + this.getGroupType() +":" +
		"roleId=" + this.getRoleId() +":"+
		"roleName=" + this.getRoleName() +":"+
		"roleType=" + this.getRoleType();
	}
}
