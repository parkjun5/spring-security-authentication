package nextstep.security;

import nextstep.app.util.Base64Convertor;
import nextstep.security.authentication.Authentication;
import nextstep.security.user.UsernamePasswordAuthenticationToken;
import org.springframework.util.StringUtils;

import java.util.Optional;

public class AuthenticationConverterV2 {


    public Optional<Authentication> convert(String headerValue) {
        if (!StringUtils.hasText(headerValue)) {
            return Optional.empty();
        }

        String credentials = headerValue.split(" ")[1];
        String decodedString = Base64Convertor.decode(credentials);
        String[] usernameAndPassword = decodedString.split(":");
        if (usernameAndPassword.length != 2) {
            return Optional.empty();
        }

        return Optional.of(UsernamePasswordAuthenticationToken.unAuthorizedToken(usernameAndPassword[0], usernameAndPassword[1]));
    }
}
