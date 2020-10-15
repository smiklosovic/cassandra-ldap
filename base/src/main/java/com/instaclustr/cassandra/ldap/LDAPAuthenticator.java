/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.ldap;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_AUTH_CACHE_ENABLED_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.PASSWORD_KEY;
import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;
import static java.util.stream.Collectors.joining;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.instaclustr.cassandra.ldap.auth.CassandraPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.DefaultLDAPServer;
import com.instaclustr.cassandra.ldap.auth.LDAPPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.cache.CredentialsCache;
import com.instaclustr.cassandra.ldap.cache.CredentialsCacheLoadingFunction;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import com.instaclustr.cassandra.ldap.hash.HasherImpl;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.config.Config;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Uses JNDI to authenticate to an LDAP server. On successful authentication a Cassandra role is created for the provided
 * user. This user is configured without a password. If LDAP server connection is lost or there is other communication error
 * while talking to LDAP server, operator has still a possibility to log in via "cassandra" user as usually and until LDAP server
 * is not back again, users meant to be authenticated against LDAP server will not be able to log in.
 *
 * Users that are disabled in LDAP can only be cleaned up manually, however this is not typically necessary as long as you
 * keep using LDAPAuthenticator, they will just needlessly fill up system_auth. As long as they are disabled in your LDAP
 * server, they cannot be authenticated with Cassandra (after expiring from the cache).
 *
 * A cache exists to stop us from spamming the LDAP server with requests. It only stores the DN of the user and should only be
 * populated if a user has successfully authenticated using LDAP previously. Expiry from the cache is configured through
 * the usual auth cache configuration option {@link Config#credentials_validity_in_ms }
 */
public class LDAPAuthenticator implements IAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(LDAPAuthenticator.class);

    private Properties properties;

    private SystemAuthRoles systemAuthRoles;

    private static final Hasher hasher = new HasherImpl();

    private CredentialsCache cache;

    public boolean requireAuthentication()
    {
        return true;
    }

    public Set<? extends IResource> protectedResources()
    {
        return Collections.emptySet();
    }

    public void validateConfiguration() throws ConfigurationException
    {
        properties = new LdapAuthenticatorConfiguration().parseProperties();
    }

    private ClientState clientState;

    private volatile boolean loggedIn = false;

    public void setup()
    {
        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException(format("%s only works with %s",
                                                    LDAPAuthenticator.class.getCanonicalName(),
                                                    CassandraAuthorizer.class.getCanonicalName()));
        }

        clientState = ClientState.forInternalCalls();

        systemAuthRoles = getService(SystemAuthRoles.class, null);
        systemAuthRoles.setClientState(clientState);
        //systemAuthRoles.waitUntilRoleIsInitialised(System.getProperty("cassandra.ldap.admin.user", "cassandra"));

        final CassandraPasswordRetriever cassandraPasswordRetriever = getService(CassandraPasswordRetriever.class, null);
        cassandraPasswordRetriever.init(clientState);

        final LDAPPasswordRetriever ldapPasswordRetriever = getService(LDAPPasswordRetriever.class, DefaultLDAPServer.class);
        try
        {
            ldapPasswordRetriever.init(clientState, hasher, properties);
        } catch (ConfigurationException e)
        {
            logger.warn(format("Not possible to connect to LDAP server as user %s.", properties.getProperty(LDAP_DN)), e);
        }

        cache = new CredentialsCache(new CredentialsCacheLoadingFunction(cassandraPasswordRetriever::retrieveHashedPassword,
                                                                         ldapPasswordRetriever::retrieveHashedPassword,
                                                                         properties.getProperty(NAMING_ATTRIBUTE_PROP)),
                                     parseBoolean(properties.getProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP)));

        logger.info("{} was initialised", LDAPAuthenticator.class.getName());
    }

    /**
     * Authenticate a user/password combination to the configured LDAP server. On the first successful authentication a corresponding
     * Cassandra role will be created.
     *
     * @param username username portion of the CN or UID. E.g "James Hook" in cn=James Hook,ou=people,o=sevenSeas
     * @param password corresponding password
     * @return {@link AuthenticatedUser} for the DN as stored in C*.
     * @throws AuthenticationException when authentication with LDAP server fails.
     */
    public AuthenticatedUser authenticate(String username, String password) throws AuthenticationException
    {
        System.out.println("Trying to login " + username + " with password " + password);

        if (!loggedIn)
        {
            // In case operator deletes cassandra role, in order to log in with a user different from cassandra,
            // one has to set below system property for Cassandra process upon start.
            // This user has to be superuser in order to be able to create roles.
            // You have to specify what is basically in ldap.properties
            // under service_dn, e.g "-Dcassandra.ldap.admin.user=cn=admin,dc=example,dc=org"
            // This name maps to system_auth.roles.role field and it has to be already present so operator
            // will likely log in with LDAP admin first in order to have that entry present in system_auth.roles

            assert clientState != null;

            clientState.login(new AuthenticatedUser(System.getProperty("cassandra.ldap.admin.user", "cassandra")));

            loggedIn = true;
        }

        try
        {
            final User user = new User(username, password);

            final String cachedPassword = cache.get(user);

            // authenticate will be called if we're not in cache, subsequently loading the cache for the given user.
            if (cachedPassword != null)
            {
                if (!hasher.checkPasswords(password, cachedPassword))
                {
                    if (user.getLdapDN() == null)
                    {
                        throw new AuthenticationException("invalid username/password");
                    }

                    // Password has changed, re-auth and store new password in cache (or fail). A bit dodgy because
                    // we don't have access to cache.put(). This has a side-effect that a bad auth will invalidate the
                    // cache for the user and the next auth for the user will have to re-populate the cache. tl;dr:
                    // don't spam incorrect passwords (or let others spam them for your user).
                    cache.invalidate(user);
                    cache.get(user);
                }

                if (user.getLdapDN() != null && user.getLdapDN().equals(properties.getProperty(LDAP_DN)))
                {
                    systemAuthRoles.createRoleIfNotExists(properties.getProperty(LDAP_DN));
                } else if (user.getLdapDN() != null && systemAuthRoles.roleMissing(user.getLdapDN()))
                {
                    logger.info("DN {} doesn't exist in {}.{}, creating new user",
                                user.getLdapDN(),
                                "system_auth",
                                AuthKeyspace.ROLES);
                    systemAuthRoles.createRole(user.getLdapDN());
                }

                final String loginName = user.getLdapDN() == null ? user.getUsername() : user.getLdapDN();

                return new AuthenticatedUser(loginName);
            }
        } catch (UncheckedExecutionException ex)
        {
            if (ex.getCause() instanceof LDAPAuthFailedException)
            {
                final LDAPAuthFailedException ldex = (LDAPAuthFailedException) ex.getCause();

                logger.warn("Failed login for {}, reason was {}", username, ex.getMessage());

                throw new AuthenticationException(format(
                    "Failed to authenticate with directory server, user may not exist: %s",
                    ldex.getMessage()));
            } else
            {
                throw ex;
            }
        } catch (Exception ex)
        {
            throw new AuthenticationException(format("Could not authenticate to the LDAP directory: %s", ex.getMessage()), ex);
        }

        return null; // should never be reached
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new PlainTextSaslAuthenticator(this);
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(final Map<String, String> credentials) throws AuthenticationException
    {
        final String username = credentials.get(LDAP_DN);

        if (username == null)
        {
            throw new AuthenticationException(format("Required key '%s' is missing", LDAP_DN));
        }

        final String password = credentials.get(PASSWORD_KEY);

        if (password == null)
        {
            throw new AuthenticationException(format("Required key '%s' is missing for provided username %s", PASSWORD_KEY, username));
        }

        return authenticate(username, password);
    }


    private <T> T getService(final Class<T> clazz, final Class<? extends T> defaultImplClazz)
    {
        final ServiceLoader<T> loader = ServiceLoader.load(clazz);
        final Iterator<T> iterator = loader.iterator();
        final List<T> services = new ArrayList<>();

        if (iterator.hasNext())
        {
            services.add(iterator.next());
        }

        if (services.isEmpty())
        {
            if (defaultImplClazz == null)
            {
                throw new IllegalStateException(format("There is no implementation of %s", clazz));
            }

            try
            {
                logger.info(format("Using default implementation of %s: %s", clazz.getName(), defaultImplClazz.getName()));
                return defaultImplClazz.newInstance();
            } catch (InstantiationException | IllegalAccessException e)
            {
                logger.error(format("Unable to instantiate default implementation of %s: %s", clazz.getName(), defaultImplClazz.getName()));
                throw new IllegalStateException(e);
            }
        }

        if (services.size() != 1)
        {
            throw new ConfigurationException(format("More than one or no implementation of %s was found: %s",
                                                    clazz.getName(),
                                                    services.stream().map(impl -> impl.getClass().getName()).collect(joining(","))));
        }

        logger.info(format("Using implementation of %s: %s", clazz.getName(), services.get(0).getClass().getName()));

        return services.get(0);
    }
}
