package com.instaclustr.cassandra.ldap.auth;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPTS;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.apache.cassandra.db.ConsistencyLevel.LOCAL_ONE;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import java.util.Properties;

import com.google.common.util.concurrent.Uninterruptibles;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public abstract class SystemAuthRoles {

    public static final String SELECT_ROLE_STATEMENT = "SELECT role FROM %s.%s where role = ?";

    public static final String CREATE_ROLE_STATEMENT_WITH_LOGIN = "CREATE ROLE \"%s\" WITH LOGIN = true";

    private ClientState clientState;

    private Properties properties;

    public void setClientState(ClientState clientState) {
        this.clientState = clientState;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }

    public ClientState getClientState() {
        return clientState;
    }

    public Properties getProperties() {
        return properties;
    }

    public abstract boolean roleMissing(String dn);

    public abstract void createRole(String roleName);

    public void createRoleIfNotExists(String serviceDN) {
        if (roleMissing(serviceDN)) {
            QueryProcessor.process(format("INSERT INTO %s.%s (role, is_superuser, can_login) VALUES ('%s', true, true)",
                                          "system_auth",
                                          AuthKeyspace.ROLES,
                                          serviceDN),
                                   ONE);
        }
    }

    public void waitUntilRoleIsInitialised(String role)
    {
        if (DatabaseDescriptor.getAuthorizer().requireAuthorization())
        {
            boolean defaultCassandraRoleExists = false;

            int attempts = 0;

            Throwable caughtException = null;

            while (!defaultCassandraRoleExists && attempts < INITIAL_CASSANDRA_LOGIN_ATTEMPTS)
            {
                Uninterruptibles.sleepUninterruptibly(INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD, SECONDS);

                attempts++;

                String cassandraUserSelect = String.format("SELECT * FROM %s.%s WHERE role = '%s'",
                                                           "system_auth",
                                                           AuthKeyspace.ROLES,
                                                           role);
                try
                {
                    defaultCassandraRoleExists = !QueryProcessor.executeInternal(cassandraUserSelect, LOCAL_ONE).isEmpty();
                }
                catch (Exception ex)
                {
                    caughtException = ex;
                }
            }

            if (!defaultCassandraRoleExists)
            {
                if (caughtException != null)
                {
                    throw new ConfigurationException("Unable to perform initial login: " + caughtException.getMessage(), caughtException);
                }
                else
                {
                    throw new ConfigurationException(String.format("There was not %s user created in %s seconds.",
                                                                   role,
                                                                   INITIAL_CASSANDRA_LOGIN_ATTEMPTS * INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD));
                }
            }
        }
    }
}
