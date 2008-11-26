package edu.wustl.securityManager.dbunit.test;

import edu.wustl.common.util.global.Constants;
import edu.wustl.security.privilege.PrivilegeType;
import junit.framework.TestCase;


public class TestPrivilegeType extends TestCase
{
	public void testGetPrivilegeTypeClass()
	{
		int value = Constants.CLASS_LEVEL_SECURE_RETRIEVE;
		PrivilegeType privilegeType = PrivilegeType.getPrivilegeType(value);
		assertEquals(PrivilegeType.ClassLevel, privilegeType);
	}
	public void testGetPrivilegeTypeObject()
	{
		int value = Constants.OBJECT_LEVEL_SECURE_RETRIEVE;
		PrivilegeType privilegeType = PrivilegeType.getPrivilegeType(value);
		assertEquals(PrivilegeType.ObjectLevel, privilegeType);
	}
	public void testGetPrivilegeTypeInsecure()
	{
		int value = Constants.INSECURE_RETRIEVE;
		PrivilegeType privilegeType = PrivilegeType.getPrivilegeType(value);
		assertEquals(PrivilegeType.InsecureLevel, privilegeType);
	}
}
