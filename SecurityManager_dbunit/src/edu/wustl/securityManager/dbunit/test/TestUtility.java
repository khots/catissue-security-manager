package edu.wustl.securityManager.dbunit.test;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import edu.wustl.common.util.global.Constants;
import edu.wustl.security.global.Utility;
import edu.wustl.security.privilege.PrivilegeType;


public class TestUtility extends TestCase
{
	public void testGetPrivilegeTypeObj()
	{
		Map <String,String> tagKeyValueMap = new HashMap<String,String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "2");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.ObjectLevel, pType);
	}
	public void testGetPrivilegeTypeClass()
	{
		Map <String,String> tagKeyValueMap = new HashMap<String,String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "1");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.ClassLevel, pType);
	}
	public void testGetPrivilegeTypeInsecure()
	{
		Map <String,String> tagKeyValueMap = new HashMap<String,String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "0");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.InsecureLevel, pType);
	}
	public void testIsBirthDateTrue()
	{
		Map <String,String> tagKeyValueMap = new HashMap<String,String>();
		tagKeyValueMap.put(edu.wustl.security.global.Constants.BDATE_TAG_NAME, Constants.TRUE);
		boolean isBirthDate = Utility.getInstance().getIsBirthDate(tagKeyValueMap);
		assertTrue(isBirthDate);
	}
	public void testIsBirthDateFalse()
	{
		Map <String,String> tagKeyValueMap = new HashMap<String,String>();
		tagKeyValueMap.put(edu.wustl.security.global.Constants.BDATE_TAG_NAME, Constants.FALSE);
		boolean isBirthDate = Utility.getInstance().getIsBirthDate(tagKeyValueMap);
		assertFalse(isBirthDate);
	}
}
