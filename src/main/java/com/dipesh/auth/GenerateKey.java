package com.dipesh.auth;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;


public class GenerateKey {

    private static String SECRET_KEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCWCHt/YJrb2TDUfmtMMxcDCqAzEGwsQZF1Ewyj9CAtZxhKBCncN2NkkcaHXSh2YS9VW7A3ciU/B5RGLozeulCrcJ23wqp/z89PkkkR1BIGi//mIqJWjyKddl+zh8lG0AJYndZpCap/CcV4uMBh/5jaCtrGuOEdkBNuKsxfwXzRA1ESV7Qgw0O0PjzUbC9JNVR7gwf+KfoP3OBvdnWUZ56hwswZpY/BiI+Qvror70a4fa/t71Es8haMdT024o3XImPHT25dlvPHAS3jxy+4BcxWUFxVyWZTJwXbYbBREkWop7ZwqE1uyW4az7rbpqyncD4b55PzY6/KQS7IMXmSIcwtAgMBAAECggEACAKd7VgQDIrVA5NYUTItGVl44iEPVXGOvYxt0VcYXLQzZMhCH+LJKLZrvhBoN6HKsCj8CInMmUfjT7fuh3m1EuIpWYVIKxjCPcJWqmADMlxJJlVVC4AK3hNS2rf2NBSo+2g56VO9yZiQ9XgPtWu7EnEf6xo10qk9kFUyoi4nZtVMkd2lKA+B8bqnH7X0W0GbjueaaA0I1DaU/j1QwXgjLHskINLjFLRv/HIluNnuLjJBPFZ4GacCHoW5diGePORz8urpw5uj0LrlJzwKik/HJbiObVhKfkMwqftuAza/kF2TIzr+I9Rr+1DbGBQ4J93hUiFrHI4B8kkkd24pjmASlQKBgQDG79ziE4VDMrDGGZZWH6XtWz9d1Htv6tPjcVv5LANFCPAwCAg9eT+parZv0Ye5u8qEC4IGDoBZp4G13XGZx00zxSvnOz3iEFtV1aPfyz7rnGJfB3DqjGM3z71AbMGdieRtINqefaAZlN1B+tXZZfjOmX+AGxe3TvB4oCANKWEDWwKBgQDBEZAuxZD4JehqxwxG9znjUhO4PE5pRqkOMvpwyl233Bw9sKvjUqLXAx+eDXYuYIldAdX1b227BsOuSHYe+LxSzqQ/B50UnOpVcswLWDsstPnngq2ocGGymLH5Bt2o1+4fn2Vl3Ur/0ZxBWgZv5J59xoqFGriCTP8BeSkhKFKtFwKBgH/FFuzs9K5QJFFXpcLy2LM14+Dz08Px4t01tYi3x/HS59Exl3lEIqtBKqNuw+l6v3tHmN8i+TSb7SdNbuUBqIgTnzsIRZqoPsFGUdYux96ztkqqkM9UE3WJK1fxgfkY02lzrHYW4XkMr37tB+R1JfQrikRRIk5NmQ0gavWJGhH5AoGAXtnHEQNkzlSpU1QI1xB8cw6Ou5N9HkFlqqEm4qS42Cwd/7y9JYgikilprheE+RHaSkQtnk+pBBo1pnjY9yxSMQhuLr0J0eepRGOKlQQ6xiL/J1rPABJ+HOThgqt52IqE5SpFAX9vajDLaFvXD7+skbQpt2zCOtmi6lFhAHYz7+8CgYAxu5JZqnA/k83z/zfLHpQFlr8RaQn9K0enVew9kK8JHDvidCCfqDiR/oM+zXCTo1WOXoev6q0osvJXsmEO4LTGQIuRgTSXswyBur6R7XyKGmK+49AIUFKb+12a/H0c0b1Q8dglYbUXmBKpvoJCSAs5RNXgePxVFWaLglkqpK74gA==";
    private static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlgh7f2Ca29kw1H5rTDMXAwqgMxBsLEGRdRMMo/QgLWcYSgQp3DdjZJHGh10odmEvVVuwN3IlPweURi6M3rpQq3Cdt8Kqf8/PT5JJEdQSBov/5iKiVo8inXZfs4fJRtACWJ3WaQmqfwnFeLjAYf+Y2graxrjhHZATbirMX8F80QNREle0IMNDtD481GwvSTVUe4MH/in6D9zgb3Z1lGeeocLMGaWPwYiPkL66K+9GuH2v7e9RLPIWjHU9NuKN1yJjx09uXZbzxwEt48cvuAXMVlBcVclmUycF22GwURJFqKe2cKhNbsluGs+626asp3A+G+eT82OvykEuyDF5kiHMLQIDAQAB";

    //Sample method to construct a JWT
    public static String createJWT(String id, String issuer, String subject) throws NoSuchAlgorithmException, InvalidKeySpecException {
       /* SECRET_KEY = SECRET_KEY.replaceAll("\n", "");*/
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(SECRET_KEY));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);

        JwtBuilder builder = Jwts.builder().setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(privKey, signatureAlgorithm);

        return builder.compact();
    }

    static Claims decodeJWT(String jwt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pubKeySpecX509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY));
        PublicKey publicKey = kf.generatePublic(pubKeySpecX509EncodedKeySpec);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwt).getBody();

        return claims;
    }

}
