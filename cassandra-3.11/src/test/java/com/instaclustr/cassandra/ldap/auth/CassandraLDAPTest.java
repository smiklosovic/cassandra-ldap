package com.instaclustr.cassandra.ldap.auth;

import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
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
        factory.getSystemProperties().put("cassandra.ldap.properties.file", Paths.get("src/test/resources/ldap.properties").toAbsolutePath().toString());
    }

    @Test
    public void testLDAP() throws Exception
    {
        CassandraClusterContext context = null;

        List<Path> pluginJars = createPluginJars();

        try
        {
            copyJars(pluginJars, getCassandraArtifact().getDistribution().getDirectory());

            context = getClusterContext(true);

            configure(context.firstFactory);
            configure(context.secondFactory);

            context.start();

            context.execute(context.firstNode, "cassandra", "cassandra", "select * from system_auth.roles");
            context.execute(context.secondNode, "cassandra", "cassandra", "select * from system_auth.roles");
            // ldap!
            context.execute(context.secondNode, "admin", "admin", "select * from system_auth.roles");
            context.execute(context.secondNode, "cn=admin,dc=example,dc=org", "admin", "select * from system_auth.roles");
        } catch (final Exception ex)
        {
            ex.printStackTrace();
        } finally
        {
            if (context != null)
            {
                context.stop();
            }

            if (pluginJars != null)
            {
                for (Path p : pluginJars)
                {
                    Files.deleteIfExists(getCassandraArtifact().getDistribution().getDirectory().resolve("lib").resolve(p.getFileName()));
                }
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