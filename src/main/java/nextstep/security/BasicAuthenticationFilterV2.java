package nextstep.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationErrorHandler;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.exception.AuthenticationException;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

public class BasicAuthenticationFilterV2 extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final AuthenticationConverterV2 converter = new AuthenticationConverterV2();

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String[] BASIC_AUTH_PATH = new String[]{"/members"};

    public BasicAuthenticationFilterV2(AuthenticationManager authenticationManager) {
        this.authenticationManager = Objects.requireNonNull(authenticationManager);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        boolean isNotGetMethod = !HttpMethod.GET.name().equalsIgnoreCase(request.getMethod());
        boolean shouldNotFilterURI = Arrays.stream(BASIC_AUTH_PATH).noneMatch(it -> it.equalsIgnoreCase(request.getRequestURI()));
        return isNotGetMethod || shouldNotFilterURI;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws IOException, ServletException {

        try {
            Optional<Authentication> authenticateRequest = converter.convert(request.getHeader(AUTHORIZATION_HEADER));
            if (authenticateRequest.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            Optional<Authentication> authentication = authenticate(authenticateRequest.get());

            authentication.ifPresent(it
                    -> SecurityContextHolder.getContext().setAuthentication(it));
        } catch (AuthenticationException e) {
            AuthenticationErrorHandler.handleError(response, e);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Optional<Authentication> authenticate(Authentication authenticateRequest) throws AuthenticationException {
            Authentication result = authenticationManager.authenticate(authenticateRequest);
            if (!result.isAuthenticated()) {
                return Optional.empty();
            }

        return Optional.of(result);
    }
}
