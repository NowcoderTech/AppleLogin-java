## APP端苹果登录java后端校验
主要校验苹果授权登录token 是否正确

## 主要方法
```
public RSAPublicKeySpec build(final String n, final String e) {
	final BigInteger modulus = new BigInteger(1, Base64.decodeBase64(n));
	final BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(e));
	return new RSAPublicKeySpec(modulus, publicExponent);
}

public int verify(final PublicKey key, final String jwt, final String audience, final String subject) {
	final JwtParser jwtParser = Jwts.parser().setSigningKey(key);
	jwtParser.requireIssuer("https://appleid.apple.com");
	jwtParser.requireAudience(audience);
	jwtParser.requireSubject(subject);
	try {
		final Jws<Claims> claim = jwtParser.parseClaimsJws(jwt);
		if (claim != null && claim.getBody().containsKey("auth_time")) {

			claims = claim;

			log.info("[Apple登录解密结果]header:{},body:{},signature:{}", claim.getHeader(), claim.getBody(),
					claim.getSignature());

			return 1;
		}
		return 0;
	} catch (final ExpiredJwtException e) {
		log.error("apple identityToken expired");
		return -1;
	} catch (final Exception e) {
		log.error("apple identityToken illegal");
		return -2;
	}
}

/**
 * 从hex string生成公钥
 * 
 * @param stringN
 * @param stringE
 * @return 构造好的公钥
 * @throws NoSuchAlgorithmException
 * @throws InvalidKeySpecException
 */
public static PublicKey createPublicKey(final String stringN, final String stringE)
		throws NoSuchAlgorithmException, InvalidKeySpecException {
	try {
		// BigInteger N = new BigInteger(stringN, 16); // hex base
		// BigInteger E = new BigInteger(stringE, 16); // hex base

		final BigInteger modulus = new BigInteger(1, Base64.decodeBase64(stringN));
		final BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(stringE));

		final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
		final KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	} catch (final Exception e) {
		e.printStackTrace();
	}

	return null;
}

```

## 需要引用到的pom包
```
<!-- 苹果登录需要用到jwt -->
<!-- 苹果登录需要用到jwt -->
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt</artifactId>
	<version>0.9.1</version>
</dependency>
<dependency>
	<groupId>com.alibaba</groupId>
	<artifactId>fastjson</artifactId>
	<version>1.2.30</version>
</dependency>

<!-- Http 请求类 -->
<dependency>
	<groupId>org.apache.httpcomponents</groupId>
	<artifactId>httpclient</artifactId>
</dependency>
<dependency>
	<groupId>com.javabase64</groupId>
	<artifactId>javabase64</artifactId>
	<version>1.3.1</version>
</dependency>

<dependency>
	<groupId>commons-lang</groupId>
	<artifactId>commons-lang</artifactId>
	<version>2.6</version>
</dependency>
```


## io.jsonwebtoken.SignatureException原因分析
一部分成功，一部分失败；报错如下：
`io.jsonwebtoken.SignatureException: JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.`

苹果官方会返回多个key，**原作者默认的取第一个，其实是有问题**
需要通过identityToken中第一部分header的kid，取匹配一个具体的key

核心代码
```
    String jwtKid = getKid(jwt);
    for (Keys key : appleKeys.keys) {
      if (StringUtils.equals(key.getKid(), jwtKid)) {
        // 注意获得kid匹配的key
        n = key.getN();
        ee = key.getE();
        logger.info(String.format("[苹果登录日志]jwt:%s,aud:%s,sub:%s", jwt, aud, sub));
        break;
      }
    }
```

参考：
https://www.jianshu.com/p/7e145d17dc0f
