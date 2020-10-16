package com.instaclustr.cassandra.ldap;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Session;
import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.github.nosan.embedded.cassandra.api.Cassandra;
import com.github.nosan.embedded.cassandra.api.Version;
import com.github.nosan.embedded.cassandra.artifact.Artifact;
import com.github.nosan.embedded.cassandra.commons.io.ClassPathResource;
import com.github.nosan.embedded.cassandra.commons.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractLDAPTest
{

    protected static final Logger logger = LoggerFactory.getLogger(AbstractLDAPTest.class);

    public Artifact getCassandraArtifact()
    {
        return Artifact.ofVersion(Version.of(getCassandraVersion()));
    }

    public String getCassandraVersion()
    {
        return System.getProperty("cassandra.version", "3.11.8");
    }

    protected EmbeddedCassandraFactory defaultNodeFactory()
    {
        EmbeddedCassandraFactory factory = new EmbeddedCassandraFactory();
        factory.getJvmOptions().add("-Xmx1g");
        factory.getJvmOptions().add("-Xms1g");

        return factory;
    }

    public CassandraClusterContext getClusterContext(boolean ldapEnabled) throws Exception
    {
        return getClusterContext(null, null, ldapEnabled);
    }

    public CassandraClusterContext getClusterContext() throws Exception
    {
        return getClusterContext(null, null, false);
    }

    public CassandraClusterContext getClusterContext(Path firstDir, Path secondDir, boolean ldap) throws Exception
    {
        EmbeddedCassandraFactory firstFactory = defaultNodeFactory();

        Path firstWorkDir = firstDir == null ? Files.createTempDirectory(null) : firstDir;

        firstFactory.setArtifact(getCassandraArtifact());
        firstFactory.setRackConfig(new ClassPathResource("cassandra1-rackdc.properties"));
        firstFactory.setWorkingDirectory(firstWorkDir);

        if (!ldap)
        {
            firstFactory.setConfig(new ClassPathResource("first.yaml"));
        } else
        {
            firstFactory.setConfig(new ClassPathResource("first-ldap.yaml"));
        }

        firstFactory.setJmxLocalPort(7199);

        EmbeddedCassandraFactory secondFactory = defaultNodeFactory();

        Path secondWorkDir = secondDir == null ? Files.createTempDirectory(null) : secondDir;

        secondFactory.setArtifact(getCassandraArtifact());
        secondFactory.setRackConfig(new ClassPathResource("cassandra2-rackdc.properties"));
        secondFactory.setWorkingDirectory(secondWorkDir);

        if (!ldap)
        {
            secondFactory.setConfig(new ClassPathResource("second.yaml"));
        } else
        {
            secondFactory.setConfig(new ClassPathResource("second-ldap.yaml"));
        }

        secondFactory.setJmxLocalPort(7200);

        CassandraClusterContext cassandraClusterContext = new CassandraClusterContext();

        cassandraClusterContext.firstFactory = firstFactory;
        cassandraClusterContext.secondFactory = secondFactory;

        cassandraClusterContext.firstWorkDir = firstWorkDir;
        cassandraClusterContext.secondWorkDir = secondWorkDir;

        return cassandraClusterContext;
    }

    protected abstract void configure(final EmbeddedCassandraFactory factory);

    public static class CassandraClusterContext
    {

        public static final Path firstNodePath = Paths.get("target/cassandra-1").toAbsolutePath();
        public static final Path secondNodePath = Paths.get("target/cassandra-2").toAbsolutePath();

        public Cassandra firstNode;
        public Cassandra secondNode;

        public EmbeddedCassandraFactory firstFactory;
        public EmbeddedCassandraFactory secondFactory;

        public Path firstWorkDir;
        public Path secondWorkDir;

        public void start()
        {
            firstNode = firstFactory.create();
            firstNode.start();
            secondNode = secondFactory.create();
            secondNode.start();
        }

        public void stop()
        {
            if (firstNode != null)
            {
                firstNode.stop();
                firstNode = null;
            }

            if (secondNode != null)
            {
                secondNode.stop();
                secondNode = null;
            }
        }

        public void execute(Cassandra node,
                            String username,
                            String password,
                            String query)
        {
            try (final Session session = Cluster.builder()
                .addContactPoints(node.getAddress())
                .withCredentials(username, password).build().connect())
            {
                ResultSet execute = session.execute(query);

                assertNotNull(execute);
                assertFalse(execute.all().isEmpty());
                assertTrue(execute.isFullyFetched());
            }
        }
    }


    protected void copyJars(List<Path> paths, Path cassandraHome) throws Exception
    {
        for (Path path : paths)
        {
            FileUtils.copy(path, cassandraHome.resolve("lib").resolve(path.getFileName()), (a, b) -> true);
        }
    }
}
