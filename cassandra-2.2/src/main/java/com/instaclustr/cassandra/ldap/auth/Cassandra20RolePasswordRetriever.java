package com.instaclustr.cassandra.ldap.auth;

import com.google.common.collect.Lists;
import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.exception.NoSuchCredentialsException;
import com.instaclustr.cassandra.ldap.exception.NoSuchRoleException;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cassandra20RolePasswordRetriever implements CassandraPasswordRetriever
{

    private static final Logger logger = LoggerFactory.getLogger(Cassandra20RolePasswordRetriever.class);

    private SelectStatement authenticateStatement;

    private static final String LEGACY_CREDENTIALS_TABLE = "credentials";
    private static final String AUTH_KEYSPACE = "system_auth";
    private SelectStatement legacyAuthenticateStatement;
    private ClientState clientState;

    @Override
    public void init(ClientState clientState)
    {
        this.clientState = clientState;
        authenticateStatement = (SelectStatement) QueryProcessor.getStatement("SELECT salted_hash FROM system_auth.roles WHERE role = ?", clientState).statement;
        if (Schema.instance.getCFMetaData(AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE) != null)
        {
            prepareLegacyAuthenticateStatementInternal(clientState);
        }
    }

    @Override
    public String retrieveHashedPassword(User user)
    {
        assert clientState != null;
        try
        {
            SelectStatement authenticationStatement = authenticationStatement(clientState);

            ResultMessage.Rows rows =
                authenticationStatement.execute(QueryState.forInternalCalls(),
                                                QueryOptions.forInternalCalls(consistencyForRole(user.getUsername()),
                                                                              Lists.newArrayList(ByteBufferUtil.bytes(user.getUsername()))));

            // If either a non-existent role name was supplied, or no credentials
            // were found for that role we don't want to cache the result so we throw
            // a specific, but unchecked, exception to keep LoadingCache happy.
            if (rows.result.isEmpty())
            {
                throw new NoSuchRoleException();
            }

            UntypedResultSet result = UntypedResultSet.create(rows.result);
            if (!result.one().has("salted_hash"))
            {
                throw new NoSuchCredentialsException();
            }

            return result.one().getString("salted_hash");
        } catch (NoSuchRoleException ex)
        {
            logger.trace(String.format("User %s does not exist in the Cassandra database.", user.getUsername()));

            throw ex;
        } catch (NoSuchCredentialsException ex)
        {
            logger.trace(String.format("User %s does not have password in the Cassandra database.", user.getUsername()));

            throw ex;
        } catch (RequestExecutionException ex)
        {
            logger.trace("Error performing internal authentication", ex);

            throw ex;
        }
    }

    /**
     * If the legacy users table exists try to verify credentials there. This is to handle the case
     * where the cluster is being upgraded and so is running with mixed versions of the auth tables
     */
    private SelectStatement authenticationStatement(ClientState clientState)
    {
        if (Schema.instance.getCFMetaData(AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE) == null)
        {
            return authenticateStatement;
        } else
        {
            // the statement got prepared, we to try preparing it again.
            // If the credentials was initialised only after statement got prepared, re-prepare (CASSANDRA-12813).
            if (legacyAuthenticateStatement == null)
            {
                prepareLegacyAuthenticateStatementInternal(clientState);
            }
            return legacyAuthenticateStatement;
        }
    }

    private void prepareLegacyAuthenticateStatementInternal(final ClientState clientState)
    {
        assert clientState != null;

        String query = String.format("SELECT salted_hash from %s.%s WHERE username = ?", AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE);
        legacyAuthenticateStatement = (SelectStatement) QueryProcessor.getStatement(query, clientState).statement;
    }

    private ConsistencyLevel consistencyForRole(String role)
    {
        if (role.equals("cassandra"))
        {
            return ConsistencyLevel.QUORUM;
        } else
        {
            return ConsistencyLevel.LOCAL_ONE;
        }
    }
}
