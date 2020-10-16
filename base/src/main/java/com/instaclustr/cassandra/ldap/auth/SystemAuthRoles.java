package com.instaclustr.cassandra.ldap.auth;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPTS;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD;
import static org.apache.cassandra.auth.AuthKeyspace.ROLES;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import java.util.Properties;
import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.Uninterruptibles;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public abstract class SystemAuthRoles
{

    public static final String SELECT_ROLE_STATEMENT = "SELECT role FROM %s.%s where role = ?";

    public static final String CREATE_ROLE_STATEMENT_WITH_LOGIN = "CREATE ROLE IF NOT EXISTS \"%s\" WITH LOGIN = true AND SUPERUSER = %s";

    private ClientState clientState;

    private Properties properties;

    public void setClientState(ClientState clientState)
    {
        this.clientState = clientState;
    }

    public void setProperties(Properties properties)
    {
        this.properties = properties;
    }

    public ClientState getClientState()
    {
        return clientState;
    }

    public Properties getProperties()
    {
        return properties;
    }

    public abstract boolean roleMissing(String dn);

    public abstract void createRole(String roleName, boolean superUser);

    public abstract boolean shouldWaitForInitialisedRole();

    public void waitUntilRoleIsInitialised(String role)
    {
        if (shouldWaitForInitialisedRole())
        {
            boolean defaultCassandraRoleExists = false;

            int attempts = 0;

            Throwable caughtException = null;

            while (!defaultCassandraRoleExists && attempts < INITIAL_CASSANDRA_LOGIN_ATTEMPTS)
            {
                Uninterruptibles.sleepUninterruptibly(INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD, TimeUnit.SECONDS);

                attempts++;

                String cassandraUserSelect = String.format("SELECT * FROM %s.%s WHERE role = '%s'",
                                                           "system_auth",
                                                           ROLES,
                                                           role);
                try
                {
                    defaultCassandraRoleExists = !QueryProcessor.process(cassandraUserSelect, ONE).isEmpty();
                } catch (Exception ex)
                {
                    caughtException = ex;
                }
            }

            if (!defaultCassandraRoleExists)
            {
                if (caughtException != null)
                {
                    throw new ConfigurationException("Unable to perform initial login: " + caughtException.getMessage(), caughtException);
                } else
                {
                    throw new ConfigurationException(String.format("There was not %s user created in %s seconds.",
                                                                   role,
                                                                   INITIAL_CASSANDRA_LOGIN_ATTEMPTS * INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD));
                }
            }
        }
    }
}
