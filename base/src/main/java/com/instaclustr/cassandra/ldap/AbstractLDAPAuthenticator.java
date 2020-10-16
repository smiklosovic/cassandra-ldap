package com.instaclustr.cassandra.ldap;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.PASSWORD_KEY;
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

import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import com.instaclustr.cassandra.ldap.hash.HasherImpl;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractLDAPAuthenticator implements IAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(AbstractLDAPAuthenticator.class);

    protected Properties properties;

    protected SystemAuthRoles systemAuthRoles;

    protected static final Hasher hasher = new HasherImpl();

    protected ClientState clientState;

    protected volatile boolean loggedIn = false;

    public abstract AuthenticatedUser authenticate(String username, String password);

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

    public <T> T getService(final Class<T> clazz, final Class<? extends T> defaultImplClazz)
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
