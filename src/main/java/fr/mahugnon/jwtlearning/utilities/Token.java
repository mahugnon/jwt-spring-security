package fr.mahugnon.jwtlearning.utilities;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data @AllArgsConstructor
public class Token {
    private String  accessToken;
    private String refreshToken;
    
}
