/*
 * Created on Oct 4, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

package edu.wustl.security.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

import edu.wustl.security.global.Constants;

import gov.nih.nci.logging.api.logger.hibernate.HibernateSessionFactoryHelper;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.exceptions.CSConfigurationException;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.util.StringUtilities;

/**
 * @author aarti_sharma
 * 
 * TODO To change the template for this generated type comment go to Window -
 * Preferences - Java - Code Style - Code Templates
 */
public class AuthorizationDAOImpl extends gov.nih.nci.security.dao.AuthorizationDAOImpl
{

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(AuthorizationDAOImpl.class);
	/**
	 * sessionFact
	 */
	private SessionFactory sessionFact = null;

	/**
	 * @param sessionFact sf
	 * @param appContextName name
	 * @throws CSConfigurationException exc
	 */
	public AuthorizationDAOImpl(SessionFactory sessionFact, String appContextName)
			throws CSConfigurationException
	{
		super(sessionFact, appContextName);
		this.sessionFact = sessionFact;

	}
	/**
	 * @param userName name
	 * @param pEs pes
	 * @throws CSException exc
	 * @return List<ObjectPrivilegeMap>list
	 */
	public List<ObjectPrivilegeMap> getPrivilegeMap(final String userName, final Collection pEs)
			throws CSException
	{
		List<ObjectPrivilegeMap> result = new ArrayList<ObjectPrivilegeMap>();
		PreparedStatement pstmt = null;
		PreparedStatement pstmt2 = null;
		Session session = null;
		Connection connection = null;

		checkForSufficientParams(userName, pEs);
		if (!pEs.isEmpty())
		{
			try
			{
				session = sessionFact.openSession();
				connection = session.connection();
				StringBuffer stbr = new StringBuffer();
				String attributeVal = "=?";
				generateQuery(stbr, attributeVal);

				StringBuffer stbr2 = new StringBuffer();
				attributeVal = " IS NULL";
				generateQuery(stbr2, attributeVal);

				String sql = stbr.toString();
				pstmt = connection.prepareStatement(sql);

				String sql2 = stbr2.toString();
				pstmt2 = connection.prepareStatement(sql2);
				result = getResult(userName, pEs, pstmt, pstmt2);
			}
			catch (SQLException ex)
			{
				StringBuffer mess = new StringBuffer("Failed to get privileges for ").append(
						userName).append(':').append(ex.getMessage());
				logger.debug(mess, ex);
				throw new CSException(mess.toString(), ex);
			}
			finally
			{
				close(pstmt, pstmt2, session, connection);
			}
		}
		return result;
	}

	/**
	 * @param pstmt stmt 1
	 * @param pstmt2 smt2
	 * @param session sess
	 * @param connection conn
	 */
	private void close(PreparedStatement pstmt, PreparedStatement pstmt2, Session session,
			Connection connection)
	{
		try
		{
			session.close();
			pstmt.close();
			pstmt2.close();
			connection.close();
		}
		catch (SQLException ex2)
		{
			logger.debug("Error in Closing Session |" + ex2.getMessage());
		}
	}

	/**
	 * @param userName userName
	 * @param pEs pes
	 * @param pstmt stmt
	 * @param pstmt2 stmt2
	 * @return list of ObjectPrivMap
	 * @throws SQLException exc
	 */
	private List<ObjectPrivilegeMap> getResult(final String userName, final Collection pEs,
			PreparedStatement pstmt, PreparedStatement pstmt2) throws SQLException
	{
		ResultSet resulSet = null;
		List<ObjectPrivilegeMap> result = new ArrayList<ObjectPrivilegeMap>();
		Iterator iterator = pEs.iterator();
		while (iterator.hasNext())
		{
			ProtectionElement pElement = (ProtectionElement) iterator.next();
			ArrayList<Privilege> privs = new ArrayList<Privilege>();
			if (pElement.getObjectId() != null)
			{
				if (pElement.getAttribute() == null)
				{
					pstmt2.setString(Constants.POSITION1, pElement.getObjectId());
					pstmt2.setString(Constants.POSITION2, userName);
					resulSet = pstmt2.executeQuery();
				}
				else
				{
					pstmt.setString(Constants.POSITION1, pElement.getObjectId());
					pstmt.setString(Constants.POSITION2, pElement.getAttribute());
					pstmt.setString(Constants.POSITION3, userName);
					resulSet = pstmt.executeQuery();
				}
			}
			while (resulSet.next())
			{
				String priv = resulSet.getString(1);
				Privilege privilege = new Privilege();
				privilege.setName(priv);
				privs.add(privilege);
			}
			resulSet.close();
			ObjectPrivilegeMap opm = new ObjectPrivilegeMap(pElement, privs);
			result.add(opm);
		}
		resulSet.close();
		return result;
	}

	/**
	 * @param userName name of the user
	 * @param pEs pes
	 * @throws CSException exc
	 */
	private void checkForSufficientParams(final String userName, final Collection pEs)
			throws CSException
	{
		if (StringUtilities.isBlank(userName))
		{
			throw new CSException("userName can't be null!");
		}
		if (pEs == null)
		{
			throw new CSException("protection elements collection can't be null!");
		}
	}

	/**
	 * @param userId string
	 * @return Set groups
	 * @throws CSObjectNotFoundException exc
	 */
	public Set getGroups(final String userId) throws CSObjectNotFoundException
	{
		Session session = null;
		Set<Group> groups = new HashSet<Group>();
		try
		{
			session = HibernateSessionFactoryHelper.getAuditSession(sessionFact);

			User user = (User) this
					.getObjectByPrimaryKey(session, User.class, Long.valueOf(userId));
			groups = user.getGroups();
			List<Group> list = new ArrayList<Group>();
			Iterator<Group> toSortIterator = groups.iterator();
			while (toSortIterator.hasNext())
			{
				list.add(toSortIterator.next());
			}
			Collections.sort(list);
			groups.clear();
			groups.addAll(list);
		}
		catch (Exception ex)
		{
			String mess = "An error occurred while obtaining Associated Groups for the User:"
					+ userId;
			logger.error(mess, ex);
			throw new CSObjectNotFoundException(mess + ex.getMessage(), ex);
		}
		finally
		{
			try
			{
				session.close();
			}
			catch (Exception ex2)
			{
				logger.debug("Error in Closing Session" + ex2.getMessage());
			}
		}
		return groups;

	}
	/**
	 * 
	 * @param session session
	 * @param objectType objType
	 * @param primaryKey pKey
	 * @return Object
	 * @throws CSObjectNotFoundException exc
	 */
	private Object getObjectByPrimaryKey(final Session session, final Class objectType,
			final Long primaryKey) throws CSObjectNotFoundException
	{

		if (primaryKey == null)
		{
			throw new CSObjectNotFoundException("The primary key can't be null");
		}
		Object obj = session.load(objectType, primaryKey);

		if (obj == null)
		{
			logger.debug("Authorization|||getObjectByPrimaryKey|Failure|Not found object of type "
					+ objectType.getName() + "|");
			throw new CSObjectNotFoundException(objectType.getName() + " not found");
		}
		logger
				.debug("Authorization|||getObjectByPrimaryKey|Success|" +
						"Success in retrieving object of type "
						+ objectType.getName() + "|");
		return obj;
	}
	/**
	 * @param stbr stringBuffer
	 * @param attributeVal string val
	 */
	private void generateQuery(StringBuffer stbr, final String attributeVal)
	{
		String str = "select distinct(p.privilege_name)" + " from csm_protection_group pg,"
				+ " csm_protection_element pe," + " csm_pg_pe pgpe,"
				+ " csm_user_group_role_pg ugrpg," + " csm_user u," + " csm_group g,"
				+ " csm_user_group ug," + " csm_role_privilege rp," + " csm_privilege p "
				+ " where pgpe.protection_group_id = pg.protection_group_id"
				+ " and pgpe.protection_element_id = pe.protection_element_id"
				+ " and pe.object_id= ?" +

				" and pe.attribute " + attributeVal
				+ " and pg.protection_group_id = ugrpg.protection_group_id "
				+ " and (( ugrpg.group_id = g.group_id" + " and ug.group_id= g.group_id"
				+ "       and ug.user_id = u.user_id)" + "       or "
				+ "     (ugrpg.user_id = u.user_id))" + " and u.login_name=?"
				+ " and ugrpg.role_id = rp.role_id " + " and rp.privilege_id = p.privilege_id";

		stbr.append(str);
	}

}