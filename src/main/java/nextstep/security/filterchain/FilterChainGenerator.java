package nextstep.security.filterchain;

import nextstep.security.BasicAuthenticationFilterV2;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.context.SecurityContextRepositoryImpl;
import nextstep.security.filter.SecurityContextLoaderFilter;
import nextstep.security.filter.UserNamePasswordAuthFilter;
import nextstep.security.filter.UserRoleFilter;

import java.util.List;

public class FilterChainGenerator {

    private final SecurityContextRepository securityContextRepository = new SecurityContextRepositoryImpl();
    private final AuthenticationManager authenticationManager;


    public FilterChainGenerator(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public SecurityFilterChain generate() {
        return new BasicSecurityFilterChain(
                List.of(
                        new SecurityContextLoaderFilter(securityContextRepository),
                        new BasicAuthenticationFilterV2(authenticationManager),
                        new UserNamePasswordAuthFilter(authenticationManager, securityContextRepository),
                        new UserRoleFilter()
                )
        );
    }
}
