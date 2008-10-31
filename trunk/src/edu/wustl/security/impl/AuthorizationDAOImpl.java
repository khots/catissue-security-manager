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
import org.hibernate.HibernateException;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import gov.nih.nci.logging.api.logger.hibernate.HibernateSessionFactoryHelper;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.exceptions.CSConfigurationException;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.exceptions.CSTransactionException;
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

	private SessionFactory sessionFact = null;

	/**
	 * @param sessionFact
	 * @param appContextName
	 * @throws CSConfigurationException
	 */
	public AuthorizationDAOImpl(SessionFactory sessionFact, String appContextName)
			throws CSConfigurationException
	{
		super(sessionFact, appContextName);
		this.sessionFact = sessionFact;

	}

	public Collection getPrivilegeMap(String userName, Collection pEs) throws CSException
	{
		ArrayList<ObjectPrivilegeMap> result = new ArrayList<ObjectPrivilegeMap>();
		ResultSet resulSet = null;
		PreparedStatement pstmt = null;
		PreparedStatement pstmt2 = null;
		Session session = null;
		Connection connection = null;

		if (StringUtilities.isBlank(userName))
		{
			throw new CSException("userName can't be null!");
		}
		if (pEs == null)
		{
			throw new CSException("protection elements collection can't be null!");
		}
		if (!pEs.isEmpty())
		{
			try
			{
				session = sessionFact.openSession();
				connection = session.connection();
				StringBuffer stbr = new StringBuffer();
				String attributeVal = "=?";
				generateQuery(stbr,attributeVal);

				StringBuffer stbr2 = new StringBuffer();
				attributeVal = " IS NULL";
				generateQuery(stbr2,attributeVal);

				String sql = stbr.toString();
				pstmt = connection.prepareStatement(sql);

				String sql2 = stbr2.toString();
				pstmt2 = connection.prepareStatement(sql2);
				Iterator iterator = pEs.iterator();
				while (iterator.hasNext())
				{
					ProtectionElement pElement = (ProtectionElement) iterator.next();
					ArrayList<Privilege> privs = new ArrayList<Privilege>();
					if (pElement.getObjectId() != null)
					{
						if (pElement.getAttribute()== null)
						{
							pstmt2.setString(1, pElement.getObjectId());
							pstmt2.setString(2, userName);
							resulSet = pstmt2.executeQuery();
						}
						else
						{
							pstmt.setString(1, pElement.getObjectId());
							pstmt.setString(2, pElement.getAttribute());
							pstmt.setString(3, userName);
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
				pstmt.close();
			}
			catch (Exception ex)
			{
				StringBuffer mess= new StringBuffer("Failed to get privileges for ")
				.append(userName).append(':').append(ex.getMessage());
				logger.debug(mess,ex);
				throw new CSException(mess.toString(), ex);
			}
			finally
			{
				try
				{
					session.close();
					resulSet.close();
					pstmt.close();
					connection.close();
				}
				catch (SQLException ex2)
				{
					logger.debug("Error in Closing Session |"+ ex2.getMessage());
				}
			}
		}
		return result;
	}

	//changes to load the object and then delete it
	//else it throws exception
	public void removeProtectionElementsFromProtectionGroup(String protectionGroupId,
			String[] protectionEleIds) throws CSTransactionException
	{
		Session session = null;
		Transaction transaction = null;

		try
		{
			session = sessionFact.openSession();
			transaction = session.beginTransaction();

			for (int i = 0; i < protectionEleIds.length; i++)
			{
				StringBuffer query = new StringBuffer("from gov.nih.nci.security.dao.hibernate.ProtectionGroupProtectionElement protectionGroupProtectionElement");
				query.append(" where protectionGroupProtectionElement.protectionElement.protectionElementId=");
				query.append(protectionEleIds[i]);
				query.append(" and protectionGroupProtectionElement.protectionGroup.protectionGroupId=");
				query.append(protectionGroupId);
				Query queryObj = session.createQuery(query.toString());
				List list = queryObj.list();
				if (list != null && !list.isEmpty())
				{
					this.removeObject(list.get(0));
				}
			}
			transaction.commit();
		}
		catch (Exception ex)
		{
			transaction.rollback();
			StringBuffer mess= new StringBuffer("Error Occured in deassigning Protection Elements ")
					.append(StringUtilities.stringArrayToString(protectionEleIds))
					.append(" to Protection Group").append( protectionGroupId);
			logger.error(mess + ex.getMessage(),ex);
			throw new CSTransactionException(mess+ ex.getMessage(), ex);
		}
		finally
		{
				session.close();
		}
	}

	public Set getGroups(String userId) throws CSObjectNotFoundException
	{
		Session session = null;
		Set groups = new HashSet();
		try
		{
			session = HibernateSessionFactoryHelper.getAuditSession(sessionFact);

			User user = (User) this.getObjectByPrimaryKey(session, User.class, Long.valueOf(userId));
			groups = user.getGroups();
			List list = new ArrayList();
			Iterator toSortIterator = groups.iterator();
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
			String mess="An error occurred while obtaining Associated Groups for the User:"+userId;
			logger.error(mess,ex);
			throw new CSObjectNotFoundException(mess+ ex.getMessage(), ex);
		}
		finally
		{
			try
			{
				session.close();
			}
			catch (Exception ex2)
			{
				logger.debug("Error in Closing Session"	+ ex2.getMessage());
			}
		}
		return groups;

	}

	private Object getObjectByPrimaryKey(Session session, Class objectType, Long primaryKey)
			throws HibernateException, CSObjectNotFoundException
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
				.debug("Authorization|||getObjectByPrimaryKey|Success|Success in retrieving object of type "
						+ objectType.getName() + "|");
		return obj;
	}
	
	private void generateQuery(StringBuffer stbr,String attributeVal)
	{
		stbr.append("select distinct(p.privilege_name)");
		stbr.append(" from csm_protection_group pg,");
		stbr.append(" csm_protection_element pe,");
		stbr.append(" csm_pg_pe pgpe,");
		stbr.append(" csm_user_group_role_pg ugrpg,");
		stbr.append(" csm_user u,");
		stbr.append(" csm_group g,");
		stbr.append(" csm_user_group ug,");
		stbr.append(" csm_role_privilege rp,");
		stbr.append(" csm_privilege p ");
		stbr.append(" where pgpe.protection_group_id = pg.protection_group_id");
		stbr.append(" and pgpe.protection_element_id = pe.protection_element_id");
		stbr.append(" and pe.object_id= ?");

		stbr.append(" and pe.attribute ").append(attributeVal);
		stbr.append(" and pg.protection_group_id = ugrpg.protection_group_id ");
		stbr.append(" and (( ugrpg.group_id = g.group_id");
		stbr.append(" and ug.group_id= g.group_id");
		stbr.append("       and ug.user_id = u.user_id)");
		stbr.append("       or ");
		stbr.append("     (ugrpg.user_id = u.user_id))");
		stbr.append(" and u.login_name=?");
		stbr.append(" and ugrpg.role_id = rp.role_id ");
		stbr.append(" and rp.privilege_id = p.privilege_id");
	}

}