package com.user.authorization.configuration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.sql.DataSource;
import java.util.UUID;

@Configuration
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain authorizationServerFilterChain(HttpSecurity http) throws Exception {
        http.with(OAuth2AuthorizationServerConfigurer.authorizationServer(), Customizer.withDefaults());

        /*OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt());*/
        return http.build();
    }

   /* @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate){
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        RegisteredClient existingClient = registeredClientRepository.findByClientId("front-client");
        if(existingClient == null){

        }
    }*/

    @Bean
    UserDetailsService inMemoryUserDetailsManager() {
        return new InMemoryUserDetailsManager(
                User.builder().username("root")
                        .password("root")
                        .roles("student").build()
        );
    }

    @Bean
    JdbcUserDetailsManager jdbc(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setEnableAuthorities(false);
        jdbcUserDetailsManager.setEnableGroups(false);
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public DataSourceInitializer dataSourceInitializer(@Qualifier("dataSource") final DataSource dataSource) {
        ResourceDatabasePopulator resourceDatabasePopulator = new ResourceDatabasePopulator();
        resourceDatabasePopulator.addScript(new ClassPathResource("script/intial_schema.sql"));
        DataSourceInitializer dataSourceInitializer = new DataSourceInitializer();
        dataSourceInitializer.setDataSource(dataSource);
        dataSourceInitializer.setDatabasePopulator(resourceDatabasePopulator);
        return dataSourceInitializer;
    }

    @Bean
    ApplicationRunner initializeUser(JdbcUserDetailsManager userDetailsManager) {
        return (args) -> {
            String userName = "root1";
            if (!userDetailsManager.userExists(userName)) {
                userDetailsManager.createUser(
                        User.builder()
                                //.roles("ROLE_USER")
                                .username(userName)
                               // .password("{bcrypt}$2a$10$jdJGhzsiIqYFpjJiYWMl/eKDOd8vdyQis2aynmFN0dgJ53XvpzzwC")
                                .password("{noop}secret")
                                .build()
                );
                userDetailsManager.createGroup("GROUP_USER", AuthorityUtils.createAuthorityList("ROLE_USER"));
                userDetailsManager.addUserToGroup(userName, "GROUP_USER");
                userDetailsManager.createGroup("GROUP_ADMINS", AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
                userDetailsManager.addUserToGroup(userName, "GROUP_ADMINS");
            }
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(inMemoryUserDetailsManager().loadUserByUsername("root").getUsername())
                .clientSecret("{noop}secret") // Use a password encoder for production
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

                .redirectUri("http://localhost:8090/login/oauth2/code/authorization-fail")
                .scope("read")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
}
