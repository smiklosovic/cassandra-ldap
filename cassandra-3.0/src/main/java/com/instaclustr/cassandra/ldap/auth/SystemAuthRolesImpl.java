package com.instaclustr.cassandra.ldap.auth;

import static java.lang.String.format;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import com.google.common.collect.Lists;
import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;

public class SystemAuthRolesImpl extends SystemAuthRoles
{

    /**
     * Check if a particular role exists in system.auth
     *
     * @param dn user's distinguished name.
     * @return True if DN exists in C* roles otherwise false
     */
    public boolean roleMissing(String dn)
    {
        assert getClientState() != null;

        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(format(SELECT_ROLE_STATEMENT,
                                                                                             "system_auth",
                                                                                             AuthKeyspace.ROLES),
                                                                                      getClientState()).statement;

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(getClientState()),
                                                        QueryOptions.forInternalCalls(ONE,
                                                                                      Lists.newArrayList(ByteBufferUtil.bytes(dn))));

        return rows.result.isEmpty();
    }

    public void createRole(String roleName, boolean superUser)
    {
        final CreateRoleStatement createStmt =
            (CreateRoleStatement) QueryProcessor.getStatement(format(CREATE_ROLE_STATEMENT_WITH_LOGIN, roleName, superUser), getClientState()).statement;

        createStmt.execute(new QueryState(getClientState()),
                           QueryOptions.forInternalCalls(ONE, Lists.newArrayList(ByteBufferUtil.bytes(roleName))));
    }

    @Override
    public boolean shouldWaitForInitialisedRole()
    {
        return DatabaseDescriptor.getAuthenticator().requireAuthentication();
    }
}
