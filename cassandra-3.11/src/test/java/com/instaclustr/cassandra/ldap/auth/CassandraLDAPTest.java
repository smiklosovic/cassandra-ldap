package com.instaclustr.cassandra.ldap.auth;

import static com.instaclustr.cassandra.ldap.AbstractLDAPTest.CassandraClusterContext.firstNodePath;
import static com.instaclustr.cassandra.ldap.AbstractLDAPTest.CassandraClusterContext.secondNodePath;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.instaclustr.cassandra.ldap.AbstractLDAPTest;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.testng.annotations.Test;

public class CassandraLDAPTest extends AbstractLDAPTest
{

    public String getCassandraVersion()
    {
        return System.getProperty("cassandra.version", "3.11.8");
    }

    @Override
    protected void configure(final EmbeddedCassandraFactory factory)
    {
//        factory.getConfigProperties().put("authenticator", "com.instaclustr.cassandra.ldap.LDAPAuthenticator");
//        factory.getConfigProperties().put("authorizer", "CassandraAuthorizer");
//        factory.getConfigProperties().put("role_manager", "com.instaclustr.cassandra.ldap.LDAPCassandraRoleManager");
        factory.getSystemProperties().put("cassandra.ldap.properties.file", Paths.get("src/test/resources/ldap.properties").toAbsolutePath().toString());
    }

    @Test
    public void testLDAP()
    {
        CassandraClusterContext normalCluster = null;
        CassandraClusterContext ldapCluster = null;

        try
        {
            List<Path> pluginJars = createPluginJars();

            normalCluster = getClusterContext();

            normalCluster.start();

            normalCluster.execute(normalCluster.firstNode, "cassandra", "cassandra", "select * from system_auth.roles");
            normalCluster.execute(normalCluster.secondNode, "cassandra", "cassandra", "select * from system_auth.roles");

            normalCluster.copyWorkingDirs();

            normalCluster.stop();

            // configure ldap for both

            ldapCluster = getClusterContext(firstNodePath, secondNodePath, true);
            configure(ldapCluster.firstFactory);
            configure(ldapCluster.secondFactory);

            // copy plugin jar to both nodes' directories

            copyJars(pluginJars, firstNodePath);
            copyJars(pluginJars, secondNodePath);

            ldapCluster.start();

            // normal

            ldapCluster.execute(ldapCluster.firstNode, "cassandra", "cassandra", "select * from system_auth.roles");
            ldapCluster.execute(ldapCluster.secondNode, "cassandra", "cassandra", "select * from system_auth.roles");

            // ldap login

            ldapCluster.stop();
        } catch (final Exception ex)
        {
            ex.printStackTrace();
            if (normalCluster != null)
            {
                normalCluster.stop();
            }
            if (ldapCluster != null)
            {
                ldapCluster.stop();
            }
        }
    }

    public List<Path> createPluginJars() throws IOException
    {
        File[] singleFile = Maven.resolver()
            .loadPomFromFile("pom.xml")
            .resolve("com.instaclustr:cassandra-ldap-3.11:1.0.0")
            .withTransitivity()
            .asFile();

        return Arrays.stream(singleFile).map(file -> file.toPath().toAbsolutePath()).collect(toList());
    }
}