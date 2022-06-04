# Spring Security JWT

### Domain
Basic form with a user class and role class
```jpaql
@Entity
User{
@Id @GeneratedValue
    private Long id;
    private String name;
    private String username;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;
}
```
```jpaql
@Entity
Role{
@Id @GeneratedValue
    private Long id;
    private String name;
}
```
- User 
  - get userByName
  - User has a collection of roles with one direction jpa mapping from user side
  - The fetch type is eager
- Roles

**Service : userservice**
- Annotations : 
  - `@Service`
  - `@RequiredArgsConstructors`
  - `@Transactional`
  - `@Slf4j`
```java
AppUser saveAppUser(AppUser appUser);
Role saveRole(Role role);
void addRoleToUser(String username, String roleName);
AppUser getAppUser(String usename);
List<AppUser> getAppUsers();
```
**Create a rest Api to manage user and roles**
- Annotations : 
  - `@RestController`
  - `@RequiredArgsConstructor`
### Security configuration
Two packages : `security` and `filters`
- Security package includes 
  - `SecurityConfig` class
#### SecurityConfig
- Implements `IbSecurityConfigurerAdapter`
- Override the method `protected void configure(AuthenticationManagerBuilder auth) throws Exception` 
```java
    @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService)
                    .passwordEncoder(passwordEncoder);
        }
``` 
 Create beans for `UserDetailsService` and `BcryptPasswordEncoder`

In the UserServiceImpl class , implements UserDetailsService class from spring and override the method `loadUserByUsername(String username)` to tell spring how to inject userDetailsService bean
```java
    @Service @AllArgsConstructor
    @Transactional @Slf4j
    public class AppUserServiceImpl implements ...,UserDetailsService {
    ...
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username);
        if(appUser == null){
          log.error("User {} not found in the database", username);
          throw new UsernameNotFoundException("User not found in the database");
        }else{
          log.info("User {} found in the database", username);
        }
        Collection<GrantedAuthority> authorities = appUser.roles().stream().map(r->new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
        return new User(appUser.getUsername(),appUser.getPassword(),authorities);
      }
    ...
    }
``` 
In the main application class create a bean to tell spring how to inject the password encoder
 ```java
    @SpringBootApplication
    public class JwtlearningApplication {
    ...
    @Bean
        BCryptPasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
    }
    ...
    }
```  
 Inject the beans `UserDetailsService` and `BcryptPasswordEncoder`

```java
        @Configuration @EnableIbSecurity
         @RequiredArgsConstructor
    public class SecurityConfig  extends IbSecurityConfigurerAdapter {
      private final UserDetailsService userDetailsService;
      private final BCryptPasswordEncoder passwordEncoder;
      ...
    }
``` 
- Override the method `protected void configure(AuthenticationManagerBuilder auth) throws Exception`
  - Disable `csrf` `http.csrf().disable()`
  - Change spring security session management policy to STATELESS ( no cookies to track the user) `http.sessionManagement().sessionCreationPolicy(STATELESS)`
  - Add permissions
  - Add a custom authentication filter `http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()))` by injecting an `AuthenticationManager` bean inherited from the superclass (`IbSecurityConfigurerAdapter`).
```java
    @Override
        protected protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().anyRequest().permitAll();
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));

        }
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
            }
``` 
To add a custom filter I need to create it. I also add the `auth0` marven dependency.
```xml
   <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.19.2</version>
        </dependency>
```
To be able to manage Json web token `jwt` ()
I create a class `CustomAthenticationFilter` that implements the interface `UsernamePasswordAuthenticationFilter`.
I override two methods   
     - `(HttpServletRequest request, HttpServletResponse response)`
It retrieves username and password from the `httpRequest` and creates and authentication token (`UsernamePasswordAuthenticationToken`).
Then authenticate the using an injected `AuthenticationManager`.
      - `successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)`
  This method is called in the filter when the authentication passes. 
  There I generate a `JWT token ` and  a `JWT refresh token` for the new logged in user.
  I created the `JWTUtils` class to help me generate this tokens.
  I then add the token to the response body in json format. 
  There also I created the `Token` helper class to hold the tokens.
      
```java
    @Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
  private final AuthenticationManager authenticationManager;

  public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    log.info("User is {} and the password is {}",username, password);
    UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(username,password);
    return authenticationManager.authenticate(authenticationToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
     User user = (User)authentication.getPrincipal();
        var jwtUtils = new JWTUtils();  
       String issuer =  request.getRequestURL().toString();
       String accessToken  = jwtUtils.generateToken(user, new Date(System.currentTimeMillis()+(10*60*1000)), issuer);
       String refreshToken = jwtUtils.generateToken(user, new Date(System.currentTimeMillis()+(30*60*1000)), issuer);
       Token token = new Token(accessToken, refreshToken);
       response.setContentType(MediaType.APPLICATION_JSON_VALUE);
       new ObjectMapper().writeValue(response.getOutputStream(),token);
  }
}
```
